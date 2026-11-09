"""Log the two test accounts in and get their tokens, so the user doesn't have to paste them.

If APIFUZZ_TOKEN_A / _B are set, they are used as they are. Otherwise, if a username and password
are set for an account (APIFUZZ_USER_A / APIFUZZ_PASSWORD_A, and the same for B), the session
manager POSTs them as JSON to the login endpoint and reads the token from the answer.

The login request goes through the same HttpClient as every check, so it obeys the allowlist.
"""

import json

from apifuzz.errors import SessionError
from apifuzz.http_client import HttpClient
from apifuzz.settings import Settings

# Where the token usually sits in a login response: {"token": "..."}, {"access_token": "..."}...
_TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "id_token")


def login(client: HttpClient, settings: Settings, username: str, password: str, account: str) -> str:
    """POST {"username", "password"} to the login path and return the bearer token."""
    url = f"{settings.base_url}/{settings.login_path.lstrip('/')}"
    exchange = client.request("POST", url, json={"username": username, "password": password})
    status = exchange.response.status_code
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
