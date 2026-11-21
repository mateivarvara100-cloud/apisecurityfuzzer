"""Finish a Google sign-in: trade the one-time code from Google's window for Google's ID token.

The web app opens Google's window from its own button (Google Identity Services, code flow in a
popup). Google answers with a code that only works together with the client secret, which only
this server has. The server trades the code for Google's ID token and hands that back; the web app
then signs in to Supabase with it (signInWithIdToken). Nothing is stored here, and Google's access
token is thrown away.
"""

from typing import Any

import httpx

TOKEN_URL = "https://oauth2.googleapis.com/token"


class GoogleSignInError(Exception):
    """Google refused the code (used, expired, or for another app): the person should try again."""


class GoogleUnavailable(Exception):
    """Google couldn't be reached, or this server has no client secret."""


class GoogleCodeExchange:
    def __init__(self, client_id: str | None, client_secret: str | None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.enabled = bool(client_id and client_secret)
        self._client_id, self._client_secret = client_id, client_secret
        self._http = httpx.Client(timeout=10, follow_redirects=False, transport=transport)

    def id_token_for(self, code: str) -> str:
        if not self.enabled:
            raise GoogleUnavailable("Google sign-in isn't set up on this server")
        try:
            response = self._http.post(TOKEN_URL, data={
                "code": code,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                # what Google's popup code flow uses instead of a redirect address
                "redirect_uri": "postmessage",
                "grant_type": "authorization_code",
            })
        except httpx.HTTPError as exc:
            raise GoogleUnavailable("Google couldn't be reached") from exc
        try:
            body: dict[str, Any] = response.json()
        except ValueError:
            body = {}
        if response.status_code == 400 or response.status_code == 401:
            # invalid_grant (used or expired code), invalid_client, ... Google's own wording stays here.
            raise GoogleSignInError(str(body.get("error") or response.status_code))
        if response.status_code != 200:
            raise GoogleUnavailable(f"Google answered {response.status_code}")
        token = body.get("id_token")
        if not isinstance(token, str) or not token:
            raise GoogleSignInError("Google sent no ID token")
        return token
