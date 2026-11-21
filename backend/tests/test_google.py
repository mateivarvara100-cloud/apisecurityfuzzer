"""POST /auth/google: trading Google's one-time code for its ID token, against a fake Google."""

from urllib.parse import parse_qs

import httpx
from fastapi.testclient import TestClient

from apifuzz_web.app import create_app
from apifuzz_web.google import TOKEN_URL, GoogleCodeExchange
from apifuzz_web.store import MemoryStore
from conftest import FakeVerifier, make_config

CODE = "4/0AVG7fiQ-one-time-code"


def client_with(answer, *, secret: str | None = "test-secret", **config):
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer(request)

    google = GoogleCodeExchange("web-client.apps.googleusercontent.com", secret, transport=httpx.MockTransport(handle))
    app = create_app(make_config(**config), store=MemoryStore(), verifier=FakeVerifier(),  # type: ignore[arg-type]
                     google=google)
    return seen, TestClient(app)


def test_a_good_code_becomes_an_id_token():
    seen, client = client_with(lambda r: httpx.Response(200, json={"id_token": "google.id.token", "access_token": "ya29.x"}))
    r = client.post("/auth/google", json={"code": CODE})
    assert r.status_code == 200
    assert r.json() == {"idToken": "google.id.token"}  # Google's access token is not passed on
    sent = seen[0]
    assert str(sent.url) == TOKEN_URL and sent.method == "POST"
    form = parse_qs(sent.content.decode())
    assert form["code"] == [CODE] and form["grant_type"] == ["authorization_code"]
    assert form["redirect_uri"] == ["postmessage"] and form["client_secret"] == ["test-secret"]


def test_no_sign_in_is_needed_to_start_one():
    _, client = client_with(lambda r: httpx.Response(200, json={"id_token": "t"}))
    assert client.post("/auth/google", json={"code": CODE}).status_code == 200  # no Authorization header


def test_a_refused_code_says_try_again_without_googles_details():
    _, client = client_with(lambda r: httpx.Response(400, json={"error": "invalid_grant", "error_description": "Bad Request"}))
    r = client.post("/auth/google", json={"code": CODE})
    assert r.status_code == 400 and "Try again" in r.json()["detail"]
    assert "invalid_grant" not in r.text


def test_google_down_or_not_set_up_is_unavailable():
    _, down = client_with(lambda r: httpx.Response(503))
    assert down.post("/auth/google", json={"code": CODE}).status_code == 503

    def unreachable(request):
        raise httpx.ConnectError("no route")

    _, offline = client_with(unreachable)
    assert offline.post("/auth/google", json={"code": CODE}).status_code == 503
    seen, unset = client_with(lambda r: httpx.Response(200, json={"id_token": "t"}), secret=None)
    assert unset.post("/auth/google", json={"code": CODE}).status_code == 503
    assert seen == []  # without a secret, Google isn't even asked


def test_an_answer_without_an_id_token_is_refused():
    _, client = client_with(lambda r: httpx.Response(200, json={"access_token": "ya29.x"}))
    r = client.post("/auth/google", json={"code": CODE})
    assert r.status_code == 400 and "ya29" not in r.text


def test_malformed_requests_are_refused_before_google_is_asked():
    seen, client = client_with(lambda r: httpx.Response(200, json={"id_token": "t"}))
    for body in [{}, {"code": ""}, {"code": "short"}, {"code": "x" * 3000}, {"code": CODE, "redirect_uri": "https://evil.test"}]:
        assert client.post("/auth/google", json=body).status_code == 400, body
    assert seen == []


def test_sign_in_attempts_are_rate_limited_per_address():
    _, client = client_with(lambda r: httpx.Response(400, json={"error": "invalid_grant"}))
    codes = [client.post("/auth/google", json={"code": CODE}).status_code for _ in range(12)]
    assert codes[:10] == [400] * 10 and codes[10:] == [429, 429]


def test_the_secret_never_shows_in_config_output():
    config = make_config(google_client_id="id", google_client_secret="very-secret")
    assert "very-secret" not in repr(config)
