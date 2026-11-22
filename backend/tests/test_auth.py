"""Token checks, with a key pair made here standing in for the Supabase project's."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from apifuzz_web.auth import AuthError, AuthUnavailable, TokenVerifier

URL = "https://project.supabase.co"
ISSUER = f"{URL}/auth/v1"
KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_KEY = ec.generate_private_key(ec.SECP256R1())


class Keys:
    """Hands out the project's public key, like PyJWKClient does after fetching the JWKS."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    def get_signing_key_from_jwt(self, token: str):
        if self.error:
            raise self.error
        jwt.get_unverified_header(token)  # a malformed token fails here, as with the real client
        return jwt.PyJWK.from_dict(jwt.algorithms.ECAlgorithm.to_jwk(KEY.public_key(), as_dict=True) | {"alg": "ES256"})


def token(key=KEY, alg="ES256", **overrides) -> str:
    now = int(time.time())
    claims = {
        "sub": "11111111-1111-4111-8111-111111111111", "email": "a@example.test", "role": "authenticated",
        "aud": "authenticated", "iss": ISSUER, "iat": now, "exp": now + 3600,
        "app_metadata": {"provider": "google"}, "user_metadata": {},
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": "k1"})


verifier = TokenVerifier(URL, keys=Keys())


def test_a_good_token():
    user = verifier.verify(token())
    assert user.id == "11111111-1111-4111-8111-111111111111"
    assert user.email == "a@example.test"


def test_a_role_in_the_token_grants_nothing():
    # There are no roles. An admin role left in app_metadata (it existed until Nov 22, 2026), or
    # one a user wrote into their own user_metadata, gives the same account as any other.
    plain = verifier.verify(token())
    assert verifier.verify(token(app_metadata={"role": "admin"})) == plain
    assert verifier.verify(token(user_metadata={"role": "admin"}, app_metadata={})) == plain
    assert not hasattr(plain, "is_admin")


@pytest.mark.parametrize(
    "bad",
    [
        token(key=OTHER_KEY),  # signed by someone else
        token(exp=int(time.time()) - 120),  # expired (past the leeway)
        token(iss="https://other.supabase.co/auth/v1"),  # another project
        token(aud="anon"),
        token(role="anon"),  # the publishable key's role, not a person
        token(role="service_role"),
        token(is_anonymous=True),  # an anonymous sign-in
        token(email=None),
        token(sub=None),
        token(exp=None),
        "not.a.token",
        "",
    ],
)
def test_bad_tokens_are_refused(bad):
    with pytest.raises(AuthError):
        verifier.verify(bad)


def test_a_symmetric_token_is_refused():
    # Only ES256/RS256 are accepted, so an HS256 token is refused whatever secret signed it. That
    # includes the public key itself, the classic "algorithm confusion" forgery.
    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = jwt.utils.base64url_encode(b'{"alg":"HS256","typ":"JWT","kid":"k1"}')
    now = int(time.time())
    body = jwt.utils.base64url_encode(
        f'{{"sub":"x","email":"x@x","role":"authenticated","aud":"authenticated","iss":"{ISSUER}",'
        f'"iat":{now},"exp":{now + 3600},"app_metadata":{{"role":"admin"}}}}'.encode()
    )
    import hashlib
    import hmac

    signature = jwt.utils.base64url_encode(hmac.new(pem, header + b"." + body, hashlib.sha256).digest())
    with pytest.raises(AuthError):
        verifier.verify((header + b"." + body + b"." + signature).decode())
    with pytest.raises(AuthError):
        verifier.verify(token(key="a-shared-secret", alg="HS256"))


def test_unsigned_tokens_are_refused():
    with pytest.raises(AuthError):
        verifier.verify(jwt.encode({"sub": "x", "role": "authenticated"}, None, algorithm="none"))


def test_keys_that_cannot_be_fetched_mean_unavailable_not_refused():
    v = TokenVerifier(URL, keys=Keys(error=jwt.PyJWKClientConnectionError("down")))
    with pytest.raises(AuthUnavailable):
        v.verify(token())


def test_an_unknown_key_id_is_refused():
    v = TokenVerifier(URL, keys=Keys(error=jwt.PyJWKClientError("no key with kid k9")))
    with pytest.raises(AuthError):
        v.verify(token())
