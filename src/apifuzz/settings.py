"""Where the scanner gets its configuration: a .env file, the environment, and CLI flags.

Precedence, highest first: an explicit CLI flag, then an environment variable (or a line in a
local .env file), then a fallback worked out from the spec. Nothing here sends any requests; it
only gathers settings and turns obvious mistakes into clear errors.
"""

import os  # read environment variables
from pathlib import Path  # read the .env file
from urllib.parse import urljoin, urlsplit  # pull the host[:port] out of a base URL

from pydantic import BaseModel  # a typed settings record

from apifuzz.errors import ApifuzzError
from apifuzz.http_client import DEFAULT_PORTS, Allowlist, Credentials

MAX_CONCURRENCY = 10  # most burst requests in flight at once; this is detection, not a load test


class ConfigError(ApifuzzError):
    """A setting is missing or malformed (e.g. no base URL, or a token that isn't set)."""


class Settings(BaseModel):
    """The settings a scan needs, after flags, environment and spec have been combined."""

    base_url: str  # the root the API is served from, e.g. "https://staging.example.com"
    allowlist: list[str]  # hosts the scanner may contact; always includes the base URL's host
    token_a: str | None = None  # bearer token for test account A (the main caller)
    token_b: str | None = None  # bearer token for test account B (used by the BOLA/IDOR check)
    require_docker: bool = False  # only scan targets confirmed as running Docker containers
    # Credentials the session manager uses to log in when a token isn't given directly.
    user_a: str | None = None
    password_a: str | None = None
    user_b: str | None = None
    password_b: str | None = None
    login_path: str = "/login"  # where the session manager POSTs the credentials
    login_format: str = "json"  # "json" or "form": how the credentials are encoded
    login_user_field: str = "username"  # the name of the username field in the login request
    login_password_field: str = "password"
    # How a token is sent. Worked out from the spec's security scheme; "Authorization: Bearer <token>"
    # when the spec doesn't say. A cookie scheme uses header "Cookie" and prefix "<name>=".
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    # Set when the API takes its key in the query string (`?api_key=<token>`) instead of a header.
    auth_query_param: str | None = None
    # Path patterns (shell style, e.g. "/posts/*") whose objects are shared between users on
    # purpose. The bola check leaves them alone.
    shared_paths: list[str] = []
    burst: int = 15  # how many identical requests the rate-limit check sends to one endpoint
    concurrency: int = 1  # how many of those burst requests are in flight at once (1 = one after another)

    @property
    def is_basic(self) -> bool:
        """HTTP basic auth: the "token" is base64("user:password"), built locally, with no login call."""
        return self.auth_query_param is None and self.auth_prefix.strip().lower() == "basic"

    def credentials(self, token: str, account: str | None = None) -> Credentials:
        """How a request logs in with `token`: e.g. {"Authorization": "Bearer abc"}, or ?api_key=abc."""
        if self.auth_query_param:
            return Credentials(params={self.auth_query_param: token}, account=account, token=token)
        return Credentials({self.auth_header: f"{self.auth_prefix}{token}"}, account=account, token=token)

    def auth_headers(self, token: str) -> Credentials:
        """Kept for callers that only have a token: the same as credentials(token)."""
        return self.credentials(token)


def load_dotenv(path: str | Path = ".env") -> dict[str, str]:
    """Read a simple KEY=VALUE .env file into a dict. Missing file -> empty dict.

    Deliberately small: no quoting rules, no interpolation, no export keyword. Blank lines and
    lines starting with '#' are ignored; surrounding whitespace and one pair of matching quotes
    around the value are stripped.
    """
    values: dict[str, str] = {}
    file = Path(path)
    if not file.is_file():
        return values
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip one surrounding pair of single or double quotes, if present.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def host_entry(url: str) -> str:
    """Return "host" or "host:port" from a URL, or raise ConfigError if it isn't a usable http(s) URL."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"base URL must be an http(s) URL with a host, got: {url!r}")
    # netloc keeps any port but also any "user@"; rebuild from the clean host and optional port.
    return f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname


def resolve_settings(
    *,
    spec: dict | None = None,
    base_url: str | None = None,
    allowlist: list[str] | None = None,
    token_a: str | None = None,
    token_b: str | None = None,
    require_docker: bool | None = None,
    shared_paths: list[str] | None = None,
    burst: int | None = None,
    concurrency: int | None = None,
    spec_source: str | None = None,
    env: dict[str, str] | None = None,
) -> Settings:
    """Combine CLI arguments, environment/.env, and the spec into one Settings object.

    `env` defaults to the real environment merged over a local .env file (the environment wins).
    Pass `env` explicitly in tests to avoid depending on the machine's real environment.
    """
    if env is None:
        # .env provides defaults; a real environment variable of the same name overrides it.
        env = {**load_dotenv(), **os.environ}

    # Extra allowlist entries come from the flag or the env.
    entries = list(allowlist) if allowlist else _split_list(env.get("APIFUZZ_ALLOWLIST"))

    base_url = base_url or env.get("APIFUZZ_BASE_URL")
    if not base_url:
        # Nobody named the target, so the spec's own "servers" entry is the only candidate. A spec
        # is just a document (often downloaded), so it may not pick the target by itself.
        base_url = _confirmed_spec_server(_base_url_from_spec(spec), spec_source, entries)
    if not base_url:
        raise ConfigError(
            "no base URL: pass --base-url, set APIFUZZ_BASE_URL, or use a spec that lists a server"
        )
    base_url = base_url.rstrip("/")  # so base_url + "/orders" doesn't double the slash

    # A base URL that got this far was confirmed by the user, so its host is allowed.
    host = host_entry(base_url)
    if host not in entries:
        entries.insert(0, host)

    auth_header, auth_prefix, auth_query_param = _auth_scheme(spec, env)
    if burst is None:
        burst = _whole_number(env, "APIFUZZ_BURST", 15)
    if not 2 <= burst <= 50:
        raise ConfigError(f"the burst size must be between 2 and 50, got: {burst}")
    if concurrency is None:
        concurrency = _whole_number(env, "APIFUZZ_CONCURRENCY", 1)
    if not 1 <= concurrency <= MAX_CONCURRENCY:
        raise ConfigError(f"the concurrency must be between 1 and {MAX_CONCURRENCY}, got: {concurrency}")
    login_format = (env.get("APIFUZZ_LOGIN_FORMAT") or "json").strip().lower()
    if login_format not in ("json", "form"):
        raise ConfigError(f"APIFUZZ_LOGIN_FORMAT must be json or form, got: {login_format!r}")

    return Settings(
        base_url=base_url,
        allowlist=entries,
        token_a=token_a or env.get("APIFUZZ_TOKEN_A") or None,
        token_b=token_b or env.get("APIFUZZ_TOKEN_B") or None,
        user_a=env.get("APIFUZZ_USER_A") or None,
        password_a=env.get("APIFUZZ_PASSWORD_A") or None,
        user_b=env.get("APIFUZZ_USER_B") or None,
        password_b=env.get("APIFUZZ_PASSWORD_B") or None,
        login_path=env.get("APIFUZZ_LOGIN_PATH") or "/login",
        login_format=login_format,
        login_user_field=env.get("APIFUZZ_LOGIN_USER_FIELD") or "username",
        login_password_field=env.get("APIFUZZ_LOGIN_PASSWORD_FIELD") or "password",
        auth_header=auth_header,
        auth_prefix=auth_prefix,
        auth_query_param=auth_query_param,
        shared_paths=list(shared_paths) if shared_paths else _split_list(env.get("APIFUZZ_SHARED")),
        burst=burst,
        concurrency=concurrency,
        # None means "not given on the command line": fall back to the env ("1", "true", "yes").
        require_docker=require_docker_setting(require_docker, env),
    )


def _whole_number(env: dict[str, str], name: str, default: int) -> int:
    try:
        return int(env.get(name) or default)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got: {env.get(name)!r}") from None


def require_docker_setting(flag: bool | None, env: dict[str, str] | None = None) -> bool:
    """--require-docker if given, else APIFUZZ_REQUIRE_DOCKER ("1", "true", "yes") from the env or .env."""
    if flag is not None:
        return flag
    if env is None:
        env = {**load_dotenv(), **os.environ}
    return env.get("APIFUZZ_REQUIRE_DOCKER", "").strip().lower() in ("1", "true", "yes")


def _origin(url: str) -> tuple[str, str | None, int | None]:
    # ("http", "localhost", 8000): scheme, host and port, with the default port filled in.
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    return parts.scheme, parts.hostname, port or DEFAULT_PORTS.get(parts.scheme)


def _is_http_url(text: str | None) -> bool:
    return text is not None and text.lower().startswith(("http://", "https://"))


def _confirmed_spec_server(server: str | None, spec_source: str | None, entries: list[str]) -> str | None:
    """The spec's server URL, but only if something other than the spec confirms it as the target.

    It is confirmed when the spec was downloaded from that same host and port (the API is
    describing itself), or when the user listed the host in --allow / APIFUZZ_ALLOWLIST.
    Otherwise the scan, and the test accounts' tokens, would go wherever a document says.
    """
    if not server:
        return None
    # Where the spec was downloaded from, or None when it is a local file.
    spec_url = spec_source if spec_source is not None and _is_http_url(spec_source) else None
    if server.startswith("/"):  # a relative server such as "/api/v1": relative to where the spec lives
        if spec_url is None:
            raise ConfigError(
                f"the spec's server is the relative path {server!r}, so the host is unknown: pass --base-url"
            )
        server = urljoin(spec_url, server)
    host_entry(server)  # raises ConfigError unless it is an http(s) URL with a host
    if spec_url is not None and _origin(spec_url) == _origin(server):
        return server
    if Allowlist(entries).permits(server):
        return server
    raise ConfigError(
        f"the spec names {server} as its server, but a spec may not choose the target on its own. "
        f"If that is the API you mean to test, pass --base-url {server}"
    )


def _auth_scheme(spec: dict | None, env: dict[str, str]) -> tuple[str, str, str | None]:
    """How to send a token: (header name, text put before the token, query parameter or None).

    APIFUZZ_AUTH_QUERY (a query parameter name), then APIFUZZ_AUTH_HEADER / APIFUZZ_AUTH_PREFIX
    win. Otherwise the spec's security scheme decides, and "Authorization: Bearer <token>" is the
    fallback. A prefix of "Basic" means HTTP basic auth.
    """
    query = (env.get("APIFUZZ_AUTH_QUERY") or "").strip()
    if query:
        return "Authorization", "", query
    header, prefix = env.get("APIFUZZ_AUTH_HEADER"), env.get("APIFUZZ_AUTH_PREFIX")
    if header or prefix:
        prefix = (prefix or "").strip()
        if prefix.isalpha():  # a word such as "Bearer" or "Token" is followed by a space
            prefix += " "
        return (header or "Authorization").strip(), prefix, None
    return _auth_scheme_from_spec(spec) or ("Authorization", "Bearer ", None)


def _auth_scheme_from_spec(spec: dict | None) -> tuple[str, str, str | None] | None:
    if not spec:
        return None
    # OpenAPI 3 keeps schemes under components.securitySchemes; Swagger 2 under securityDefinitions.
    schemes = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
    if not isinstance(schemes, dict) or not schemes:
        return None
    # Prefer the scheme the spec applies to every operation; otherwise the first one declared.
    names = [n for req in spec.get("security") or [] if isinstance(req, dict) for n in req]
    scheme = next((schemes[n] for n in names if n in schemes), next(iter(schemes.values())))
    if not isinstance(scheme, dict):
        return None
    kind, name = scheme.get("type"), scheme.get("name")
    if kind == "apiKey" and isinstance(name, str) and name:
        if scheme.get("in") == "header":
            return name, "", None
        if scheme.get("in") == "cookie":
            return "Cookie", f"{name}=", None
        if scheme.get("in") == "query":
            return "Authorization", "", name
    # OpenAPI 3 says "type: http, scheme: basic"; Swagger 2 says "type: basic".
    if (kind == "http" and str(scheme.get("scheme", "")).lower() == "basic") or kind == "basic":
        return "Authorization", "Basic ", None
    return None  # bearer, OAuth2 and anything unknown: the Authorization: Bearer fallback


def _split_list(value: str | None) -> list[str]:
    # Turn "a, b ,c" into ["a", "b", "c"], dropping empties and whitespace.
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _base_url_from_spec(spec: dict | None) -> str | None:
    # OpenAPI 3: the first "servers" entry. Swagger 2: host + basePath + the first scheme.
    if not spec:
        return None
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url")
        if isinstance(url, str) and url:
            return url
    host = spec.get("host")  # Swagger 2
    if isinstance(host, str) and host:
        schemes = spec.get("schemes") or ["https"]
        scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
        base_path = spec.get("basePath") or ""
        return f"{scheme}://{host}{base_path}"
    return None
