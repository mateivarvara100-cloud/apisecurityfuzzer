"""Log the two test accounts in, and make sure their tokens work before the scan relies on them.

If APIFUZZ_TOKEN_A / _B are set, they are used as they are. Otherwise, if a username and password
are set for an account (APIFUZZ_USER_A / APIFUZZ_PASSWORD_A, and the same for B), the session
manager POSTs them to the login endpoint and reads the token from the answer. The credentials are
sent as JSON by default, or as form fields with APIFUZZ_LOGIN_FORMAT=form.

With HTTP basic auth (the spec's scheme, or APIFUZZ_AUTH_PREFIX=Basic) nothing is POSTed: the
"token" is base64("user:password"), sent as "Authorization: Basic ...".

`preflight` then checks the tokens. A scan with a dead token gets 401 everywhere and would report
"no findings" for an API it never tested, and a scan where A and B are the same user would
"prove" that two accounts can read each other's data. Both stop the scan here instead.

A token can also expire during a scan. `Reauthenticator` logs the account in again when that
happens (see its docstring for how it tells an expired token from an ordinary 401).

Every request goes through the same HttpClient as the checks, so it obeys the allowlist.
"""

import base64
import json
import threading
import time

from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import SessionError
from apifuzz.http_client import Credentials, HttpClient
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
            if settings.is_basic:
                updates[f"token_{account}"] = basic_token(username, password)
            else:
                updates[f"token_{account}"] = login(client, settings, username, password, account.upper())
    return settings.model_copy(update=updates) if updates else settings


def basic_token(username: str, password: str) -> str:
    """The value HTTP basic auth sends after "Basic ": base64 of "username:password"."""
    return base64.b64encode(f"{username}:{password}".encode()).decode("ascii")


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


MAX_REFRESHES = 3  # fresh logins per account per scan; more than that means something else is wrong
_STILL_VALID_FOR = 30.0  # seconds a token confirmed as working is trusted without asking again


class Reauthenticator:
    """Log a test account in again when its token stops working in the middle of a scan.

    The HttpClient calls this with the credentials of a request that was answered 401. A 401 is
    often the API's real answer (a cross-account probe, say), so a fresh login happens only when
    the token itself turns out to be dead:

    1. If the account already has a newer token (an earlier 401 refreshed it), retry with that.
    2. If the account has no username/password (a token was given directly, or basic auth), or
       has used up its MAX_REFRESHES, the 401 stands.
    3. The token is tried on a protected "who am I" endpoint, the same kind preflight uses. If
       that works, the token is fine and the 401 stands. The answer is remembered for 30 seconds,
       so a burst of 401s costs one extra request, not one each.
    4. Otherwise log in again, store the new token in the settings (so every later request uses
       it), and retry with it. A login that fails stops the scan: carrying on with a dead token
       would report a clean API that was never tested.

    The replaced tokens are kept in `retired`, so reports can redact them too.
    """

    def __init__(self, client: HttpClient, settings: Settings, endpoints: list[Endpoint]) -> None:
        self._client = client
        self._settings = settings  # the same object the checks read their tokens from
        self._probes = _probe_endpoints(endpoints)
        self._lock = threading.Lock()  # bursts may be sent from several threads
        self._refreshes = {"a": 0, "b": 0}
        self._confirmed: dict[str, float] = {}  # token -> when it was last seen working
        self.retired: list[str] = []
        self.notes: list[str] = []  # one line per fresh login, for the scan's warnings

    def __call__(self, credentials: Credentials) -> Credentials | None:
        account = credentials.account
        if account not in ("a", "b"):
            return None
        with self._lock:
            current = getattr(self._settings, f"token_{account}")
            if current and credentials.token != current:
                return self._settings.credentials(current, account)  # already refreshed
            username = getattr(self._settings, f"user_{account}")
            password = getattr(self._settings, f"password_{account}")
            if not (username and password) or self._settings.is_basic:
                return None
            if self._refreshes[account] >= MAX_REFRESHES:
                return None
            if self._still_works(credentials):
                return None  # the token is fine: the 401 is the API's answer to that request
            self._refreshes[account] += 1
            fresh = login(self._client, self._settings, username, password, account.upper())
            if fresh == current:
                # The login hands out the same token, so a retry would get the same 401.
                self._refreshes[account] = MAX_REFRESHES
                return None
            if current:
                self.retired.append(current)
            setattr(self._settings, f"token_{account}", fresh)
            self.notes.append(f"account {account.upper()}'s token stopped working mid-scan; logged in again")
            return self._settings.credentials(fresh, account)

    def _still_works(self, credentials: Credentials) -> bool:
        token = credentials.token or ""
        seen = self._confirmed.get(token)
        if seen is not None and time.monotonic() - seen < _STILL_VALID_FOR:
            return True
        if not self._probes:
            return False  # nothing to test it on: assume it expired, as the 401 suggests
        endpoint = self._probes[0]
        url = f"{self._settings.base_url}/{endpoint.path.lstrip('/')}"
        exchange = self._client.request("GET", url, headers=credentials, refresh=False)
        if exchange.response.status_code == 401:
            return False
        self._confirmed[token] = time.monotonic()
        return True
