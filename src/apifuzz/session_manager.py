"""Log the two test accounts in, and make sure their tokens work before the scan relies on them.

If APIFUZZ_TOKEN_A / _B are set, they are used as they are. Otherwise, if a username and password
are set for an account (APIFUZZ_USER_A / APIFUZZ_PASSWORD_A, and the same for B), the session
manager POSTs them to the login endpoint and reads the token from the answer. The credentials are
sent as JSON by default, or as form fields with APIFUZZ_LOGIN_FORMAT=form.

`preflight` then checks the tokens. A scan with a dead token gets 401 everywhere and would report
"no findings" for an API it never tested, and a scan where A and B are the same user would
"prove" that two accounts can read each other's data. Both stop the scan here instead.

Every request goes through the same HttpClient as the checks, so it obeys the allowlist.
"""

import json

from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import SessionError
from apifuzz.http_client import HttpClient
from apifuzz.settings import Settings

# Where the token usually sits in a login response: {"token": "..."}, {"access_token": "..."}...
_TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "id_token")
# Last path segments of endpoints that describe the caller, e.g. GET /me or GET /users/me.
IDENTITY_NAMES = {"me", "whoami", "self", "profile", "account", "userinfo", "current"}
_MAX_PREFLIGHT_TRIES = 3  # protected endpoints to try per account before giving up


def login(client: HttpClient, settings: Settings, username: str, password: str, account: str) -> str:
    """POST the username and password to the login path and return the token from the answer."""
    url = f"{settings.base_url}/{settings.login_path.lstrip('/')}"
    credentials = {settings.login_user_field: username, settings.login_password_field: password}
    if settings.login_format == "form":
        exchange = client.request("POST", url, data=credentials)
    else:
        exchange = client.request("POST", url, json=credentials)
    status = exchange.response.status_code
    if status == 429:
        raise SessionError(
            f"logging in account {account} at {url} failed: HTTP 429. The login endpoint is "
            "rate-limiting this client (perhaps after an earlier scan); wait a little and try again."
        )
    if not exchange.response.ok:
        raise SessionError(f"logging in account {account} at {url} failed: HTTP {status}")
    try:
        body = json.loads(exchange.response.body)
    except ValueError:
        body = None
    if isinstance(body, dict):
        for key in _TOKEN_KEYS:
            if isinstance(body.get(key), str) and body[key]:
                return body[key]
    raise SessionError(
        f"logging in account {account} at {url} worked (HTTP {status}), but the answer has no token "
        f"field ({', '.join(_TOKEN_KEYS)})"
    )


def authenticate(client: HttpClient, settings: Settings) -> Settings:
    """Return settings with token_a / token_b filled in by logging in where credentials are given."""
    updates: dict[str, str] = {}
    for account in ("a", "b"):
        if getattr(settings, f"token_{account}"):
            continue  # an explicit token wins
        username, password = getattr(settings, f"user_{account}"), getattr(settings, f"password_{account}")
        if username and password:
            updates[f"token_{account}"] = login(client, settings, username, password, account.upper())
    return settings.model_copy(update=updates) if updates else settings


def _is_identity(endpoint: Endpoint) -> bool:
    return endpoint.path.rstrip("/").rsplit("/", 1)[-1].lower() in IDENTITY_NAMES


def _probe_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Protected GET endpoints that can be called as they are, "who am I" style ones first."""
    usable = [
        e
        for e in endpoints
        if e.method == "GET"
        and e.requires_auth
        and "{" not in e.path
        and not any(p.required and p.location in ("path", "query") for p in e.parameters)
    ]
    return sorted(usable, key=lambda e: not _is_identity(e))[:_MAX_PREFLIGHT_TRIES]  # stable sort


def preflight(client: HttpClient, settings: Settings, endpoints: list[Endpoint]) -> list[str]:
    """Check the test accounts before scanning. Raises SessionError when they can't be used.

    - A and B must not have the same token.
    - Each token must be accepted by a protected endpoint. If every one tried answers 401 or 403,
      the token is expired or wrong.
    - On a "who am I" endpoint such as /me, A and B must not get the same answer: that would mean
      both tokens belong to one user.

    Returns warnings for what it could not confirm (for example, the spec has no protected
    endpoint that can be called without inventing a value).
    """
    tokens = {"A": settings.token_a, "B": settings.token_b}
    if tokens["A"] and tokens["A"] == tokens["B"]:
        raise SessionError(
            "accounts A and B have the same token. The bola check compares two different users, "
            "so give B the token of a second test account."
        )

    warnings: list[str] = []
    probes = _probe_endpoints(endpoints)
    identity: dict[str, tuple[str, str]] = {}  # account -> (path, body) from a "who am I" endpoint
    for account, token in tokens.items():
        if not token:
            continue
        if not probes:
            warnings.append(
                f"could not confirm account {account}'s token works: the spec has no protected GET "
                "endpoint that can be called without parameters"
            )
            continue
        refused: list[str] = []
        accepted = False
        for endpoint in probes:
            url = f"{settings.base_url}/{endpoint.path.lstrip('/')}"
            exchange = client.request("GET", url, headers=settings.auth_headers(token))
            status = exchange.response.status_code
            if exchange.response.ok:
                accepted = True
                if _is_identity(endpoint):
                    identity[account] = (endpoint.path, exchange.response.body)
                break
            if status in (401, 403):
                refused.append(f"GET {endpoint.path} answered HTTP {status}")
        if accepted:
            continue
        if refused and len(refused) == len(probes):
            raise SessionError(
                f"account {account}'s token was refused ({'; '.join(refused)}). It may be expired or "
                "wrong. Scanning with it would test nothing and report a clean API."
            )
        warnings.append(f"could not confirm account {account}'s token works: no protected endpoint answered 2xx")

    if len(identity) == 2 and identity["A"] == identity["B"] and identity["A"][1].strip():
        raise SessionError(
            f"accounts A and B look like the same user: GET {identity['A'][0]} gave both the same "
            "answer. The bola check needs two different users."
        )
    return warnings
