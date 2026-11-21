"""Who is calling: verify the Supabase access token sent with each request.

Supabase signs its tokens with an asymmetric key (ES256 for this project) and publishes the public
half at /auth/v1/.well-known/jwks.json, so the server needs no secret to check them. A token is
accepted only if its signature, expiry, issuer and audience all check out.

The role comes from `app_metadata.role`, which only the project owner can set (dashboard or SQL).
`user_metadata` is deliberately ignored: any user can write to it, so a role there would let
anyone make themselves an admin.
"""

from dataclasses import dataclass
from typing import Any, Protocol

import jwt


class AuthError(Exception):
    """The token is missing, malformed, expired or not from this project: answer 401."""


class AuthUnavailable(Exception):
    """Supabase's public keys could not be fetched, so no token can be checked: answer 503."""


@dataclass(frozen=True)
class User:
    id: str  # Supabase's user id (the token's `sub`)
    email: str
    is_admin: bool


class KeySource(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


# Asymmetric algorithms only. HS256 would mean trusting a shared secret, and accepting it next to
# ES256 is how "algorithm confusion" attacks work.
ALGORITHMS = ["ES256", "RS256"]
LEEWAY_S = 30  # small allowance for clock drift between Supabase and this server


class TokenVerifier:
    def __init__(self, supabase_url: str, keys: KeySource | None = None) -> None:
        self.issuer = f"{supabase_url}/auth/v1"
        # PyJWKClient caches the keys and fetches again only for a key id it hasn't seen.
        self._keys = keys or jwt.PyJWKClient(
            f"{self.issuer}/.well-known/jwks.json", cache_keys=True, lifespan=600, timeout=5
        )

    def verify(self, token: str) -> User:
        try:
            key = self._keys.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as exc:
            raise AuthUnavailable("could not fetch the sign-in keys") from exc
        except (jwt.PyJWKClientError, jwt.DecodeError) as exc:
            raise AuthError("not a valid sign-in token") from exc
        try:
            claims = jwt.decode(
                token,
                key.key if hasattr(key, "key") else key,
                algorithms=ALGORITHMS,
                audience="authenticated",
                issuer=self.issuer,
                leeway=LEEWAY_S,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("the sign-in has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError("not a valid sign-in token") from exc
        # A signed-in person. Not the anon role, and not an anonymous sign-in (no e-mail, no owner).
        if claims.get("role") != "authenticated" or claims.get("is_anonymous") is True:
            raise AuthError("this kind of sign-in can't run scans")
        sub, email = claims.get("sub"), claims.get("email")
        if not isinstance(sub, str) or not sub or not isinstance(email, str) or not email:
            raise AuthError("the sign-in token has no user")
        app_metadata = claims.get("app_metadata")
        is_admin = isinstance(app_metadata, dict) and app_metadata.get("role") == "admin"
        return User(id=sub, email=email, is_admin=is_admin)
