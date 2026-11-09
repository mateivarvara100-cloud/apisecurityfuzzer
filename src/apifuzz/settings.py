"""Where the scanner gets its configuration: a .env file, the environment, and CLI flags.

Precedence, highest first: an explicit CLI flag, then an environment variable (or a line in a
local .env file), then a fallback worked out from the spec. Nothing here sends any requests; it
only gathers settings and turns obvious mistakes into clear errors.
"""

import os  # read environment variables
from pathlib import Path  # read the .env file
from urllib.parse import urlsplit  # pull the host[:port] out of a base URL

from pydantic import BaseModel  # a typed settings record

from apifuzz.errors import ApifuzzError


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
    env: dict[str, str] | None = None,
) -> Settings:
    """Combine CLI arguments, environment/.env, and the spec into one Settings object.

    `env` defaults to the real environment merged over a local .env file (the environment wins).
    Pass `env` explicitly in tests to avoid depending on the machine's real environment.
    """
    if env is None:
        # .env provides defaults; a real environment variable of the same name overrides it.
        env = {**load_dotenv(), **os.environ}

    base_url = base_url or env.get("APIFUZZ_BASE_URL") or _base_url_from_spec(spec)
    if not base_url:
        raise ConfigError(
            "no base URL: pass --base-url, set APIFUZZ_BASE_URL, or use a spec that lists a server"
        )
    base_url = base_url.rstrip("/")  # so base_url + "/orders" doesn't double the slash

    # The base URL's own host is always allowed; extra entries come from the flag or the env.
    entries = list(allowlist) if allowlist else _split_list(env.get("APIFUZZ_ALLOWLIST"))
    host = host_entry(base_url)
    if host not in entries:
        entries.insert(0, host)

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
        # None means "not given on the command line": fall back to the env ("1", "true", "yes").
        require_docker=(
            require_docker
            if require_docker is not None
            else env.get("APIFUZZ_REQUIRE_DOCKER", "").strip().lower() in ("1", "true", "yes")
        ),
    )


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
