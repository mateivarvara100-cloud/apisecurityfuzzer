"""The items left open after Phase 3: wider injection coverage, more login methods, token refresh,
and concurrent rate-limit bursts. Each test runs against a fake network, so it pins the behaviour
without a live API; the lab-wide ground truth lives in test_phase1_complete.py.
"""

import base64
import threading
import time
from urllib.parse import unquote

import httpx
import pytest

from apifuzz.checks.base import NOT_TESTED, TESTED, ScanContext
from apifuzz.checks.injection import Injection
from apifuzz.checks.rate_limit import RateLimit
from apifuzz.endpoint_model import Endpoint, Parameter, build_endpoints
from apifuzz.http_client import Allowlist, Credentials, HttpClient
from apifuzz.session_manager import MAX_REFRESHES, Reauthenticator, authenticate, basic_token
from apifuzz.settings import ConfigError, Settings, resolve_settings

BASE = "http://localhost:8000"
PRODUCTS = ["book", "lamp", "mug", "pen"]


def _client(handler) -> HttpClient:
    return HttpClient(Allowlist(["localhost:8000"]), transport=httpx.MockTransport(handler))


def _ctx(handler, **settings) -> ScanContext:
    s = Settings(base_url=BASE, allowlist=["localhost:8000"], **settings)
    return ScanContext(_client(handler), s)


def _rows_for(value: str) -> httpx.Response:
    """Stand-in for `WHERE name = '<value>'` with the value pasted into the query text."""
    if value == "apifuzz'":
        return httpx.Response(500, json={"error": "SQL error: unrecognized token"})
    if "OR '1'='1'" in value:
        return httpx.Response(200, json=PRODUCTS)  # always true: every row
    if "AND '1'='2'" in value:
        return httpx.Response(404, json={"error": "not found"})  # always false: nothing
    return httpx.Response(200, json=[value]) if value in PRODUCTS else httpx.Response(404, json={"error": "not found"})


# ---------------------------------------------------------------------------------------------
# injection: path parameters and headers


ITEM = Endpoint(path="/items/{name}", method="GET", parameters=[Parameter(name="name", location="path", type="string")])
STOCK = Endpoint(
    path="/stock", method="GET",
    parameters=[Parameter(name="X-Warehouse", location="header", required=True, type="string")],
)


def _last_segment(request: httpx.Request) -> str:
    """The path value as the server sees it, percent-encoding undone."""
    return unquote(request.url.raw_path.decode().split("?")[0].rsplit("/", 1)[-1])


class TestPathInjection:
    # A path value pasted into a query is found by its database error, and keyed apart from a
    # query parameter of the same name.
    def test_error_based(self):
        ctx = _ctx(lambda r: _rows_for(_last_segment(r)))
        (finding,) = Injection().run(ITEM, ctx)
        assert finding.key == "path:name" and "Path parameter" in finding.title
        assert ctx.outcomes[("injection", "GET /items/{name}")] == (TESTED, "")

    # No error leaks, but always-true finds rows (200) and always-false finds none (404).
    def test_boolean_differential_with_404(self):
        def handler(request):
            value = _last_segment(request)
            if value == "apifuzz'":
                return httpx.Response(404, json={"error": "not found"})  # errors are hidden
            return _rows_for(value)

        (finding,) = Injection().run(ITEM, _ctx(handler))
        assert "boolean differential" in finding.detail

    # An endpoint that treats the path value as data answers 404 to every made-up name: clean,
    # and still counted as tested (404 is a real answer for a path value).
    def test_clean_path_is_tested(self):
        ctx = _ctx(lambda r: httpx.Response(404, json={"error": "not found"}))
        assert list(Injection().run(ITEM, ctx)) == []
        assert ctx.outcomes[("injection", "GET /items/{name}")] == (TESTED, "")

    # A path value on DELETE names an object to remove: it is never probed.
    def test_delete_path_is_left_alone(self):
        seen = []
        ctx = _ctx(lambda r: seen.append(r) or httpx.Response(200, json={}))
        endpoint = ITEM.model_copy(update={"method": "DELETE"})
        assert list(Injection().run(endpoint, ctx)) == [] and seen == []


class TestHeaderInjection:
    def test_header_is_probed_and_found(self):
        sent = []

        def handler(request):
            sent.append(request.headers.get("X-Warehouse"))
            return _rows_for(request.headers.get("X-Warehouse", ""))

        (finding,) = Injection().run(STOCK, _ctx(handler))
        assert finding.key == "header:X-Warehouse" and "Header 'X-Warehouse'" in finding.title
        assert all(v == v.rstrip() for v in sent)  # header values never end in whitespace

    # The boolean pair alone (no error leaked) is enough, sent as a valid header value.
    def test_header_boolean_differential(self):
        def handler(request):
            value = request.headers.get("X-Warehouse", "")
            return httpx.Response(200, json=[]) if value == "apifuzz'" else _rows_for(value)

        (finding,) = Injection().run(STOCK, _ctx(handler))
        assert "boolean differential" in finding.detail

    # The login header and standard headers are never probed, even when the spec declares them.
    def test_login_and_standard_headers_are_skipped(self):
        endpoint = Endpoint(path="/x", method="GET", requires_auth=True, parameters=[
            Parameter(name="Authorization", location="header", required=True, type="string"),
            Parameter(name="Accept", location="header", type="string"),
        ])
        seen = []
        ctx = _ctx(lambda r: seen.append(r) or httpx.Response(200, json=[]), token_a="tok")
        assert list(Injection().run(endpoint, ctx)) == [] and seen == []

    # A required header is sent with a sample on every probe of another input, and the login
    # survives the merge.
    def test_required_header_rides_along(self):
        endpoint = Endpoint(path="/stock", method="GET", requires_auth=True, parameters=[
            Parameter(name="X-Warehouse", location="header", required=True, type="string"),
            Parameter(name="q", location="query", type="string"),
        ])
        seen = []
        ctx = _ctx(lambda r: seen.append(r) or httpx.Response(200, json=[]), token_a="tok")
        list(Injection().run(endpoint, ctx))
        query_probes = [r for r in seen if "q" in r.url.params]
        assert query_probes and all(r.headers["X-Warehouse"] == "apifuzz" for r in query_probes)
        assert all(r.headers["Authorization"] == "Bearer tok" for r in seen)


# ---------------------------------------------------------------------------------------------
# login methods: API key in the query string, HTTP basic auth


def _spec(scheme: dict) -> dict:
    return {
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "security": [{"s": []}],
        "components": {"securitySchemes": {"s": scheme}}, "paths": {},
    }


class TestQueryApiKey:
    def test_from_spec(self):
        s = resolve_settings(spec=_spec({"type": "apiKey", "in": "query", "name": "api_key"}), base_url=BASE, env={})
        assert s.auth_query_param == "api_key"
        creds = s.credentials("tok", "a")
        assert dict(creds) == {} and creds.params == {"api_key": "tok"} and bool(creds)

    def test_from_env(self):
        s = resolve_settings(base_url=BASE, env={"APIFUZZ_AUTH_QUERY": "key"})
        assert s.credentials("tok").params == {"key": "tok"}

    # The key is added to the URL, next to the request's own query values.
    def test_sent_in_the_query_string(self):
        seen = []
        client = _client(lambda r: seen.append(r) or httpx.Response(200))
        creds = Credentials(params={"api_key": "tok"})
        client.request("GET", f"{BASE}/search", headers=creds, params={"q": "x"})
        assert seen[0].url.params["api_key"] == "tok" and seen[0].url.params["q"] == "x"
        assert "authorization" not in seen[0].headers

    # A check that asks "is there an account?" gets yes, though there is no header.
    def test_counts_as_an_account(self):
        ctx = _ctx(lambda r: httpx.Response(200), token_a="tok", auth_query_param="api_key")
        assert ctx.auth("a") and ctx.auth("a").params == {"api_key": "tok"}


class TestBasicAuth:
    @pytest.mark.parametrize("scheme", [{"type": "http", "scheme": "basic"}, {"type": "basic"}])
    def test_from_spec(self, scheme):
        s = resolve_settings(spec=_spec(scheme), base_url=BASE, env={})
        assert s.auth_prefix == "Basic " and s.is_basic

    # No login request: the username and password become the basic-auth value directly.
    def test_no_login_request(self):
        seen = []
        s = Settings(base_url=BASE, allowlist=["localhost:8000"], auth_prefix="Basic ",
                     user_a="alice", password_a="pw", user_b="bob", password_b="pw2")
        s = authenticate(_client(lambda r: seen.append(r) or httpx.Response(500)), s)
        assert seen == []
        assert s.token_a == base64.b64encode(b"alice:pw").decode() == basic_token("alice", "pw")
        assert s.credentials(s.token_a) == {"Authorization": f"Basic {s.token_a}"}


# ---------------------------------------------------------------------------------------------
# token refresh after a 401 mid-scan


ME = Endpoint(path="/me", method="GET", requires_auth=True)


class FakeAuthApi:
    """Accepts the tokens in `valid`; POST /login hands out the next token in `issued`."""

    def __init__(self, issued=("tok2", "tok3", "tok4", "tok5")):
        self.valid = {"tok1"}
        self.issued = list(issued)
        self.logins = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            self.logins += 1
            token = self.issued.pop(0)
            self.valid = {token}
            return httpx.Response(200, json={"token": token})
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if token not in self.valid:
            return httpx.Response(401, json={"error": "expired"})
        if request.url.path == "/secret":
            return httpx.Response(401, json={"error": "not for you"})  # a real 401 to a valid token
        return httpx.Response(200, json={"me": token})


def _refreshing(api, **settings):
    s = Settings(base_url=BASE, allowlist=["localhost:8000"], token_a="tok1", user_a="alice", password_a="pw", **settings)
    client = _client(api)
    reauth = Reauthenticator(client, s, [ME])
    client.reauthenticate = reauth
    return client, s, reauth


class TestTokenRefresh:
    # The token expires: the account logs in again, the request is retried with the new token,
    # and later requests use it straight away.
    def test_expired_token_is_renewed(self):
        api = FakeAuthApi()
        client, settings, reauth = _refreshing(api)
        api.valid = set()  # tok1 expires
        ex = client.request("GET", f"{BASE}/orders", headers=settings.credentials("tok1", "a"))
        assert ex.response.status_code == 200 and ex.request.headers["authorization"] == "Bearer tok2"
        assert settings.token_a == "tok2" and reauth.retired == ["tok1"] and api.logins == 1
        assert reauth.notes == ["account A's token stopped working mid-scan; logged in again"]
        # A check still holding the old credentials is switched to the new token without a login.
        ex = client.request("GET", f"{BASE}/orders", headers=Credentials({"Authorization": "Bearer tok1"}, account="a", token="tok1"))
        assert ex.response.status_code == 200 and api.logins == 1

    # A 401 to a working token is the API's answer, not an expiry: no login, the 401 stands.
    # The token check is remembered, so a run of such 401s costs one extra request in all.
    def test_real_401_is_kept(self):
        api = FakeAuthApi()
        client, settings, _ = _refreshing(api)
        for _ in range(3):
            assert client.request("GET", f"{BASE}/secret", headers=settings.credentials("tok1", "a")).response.status_code == 401
        assert api.logins == 0 and client.requests_sent == 4  # 3 requests + 1 token check

    # A token given directly (no username/password) can't be renewed: the 401 stands.
    def test_without_credentials_nothing_happens(self):
        api = FakeAuthApi()
        s = Settings(base_url=BASE, allowlist=["localhost:8000"], token_a="tok1")
        client = _client(api)
        client.reauthenticate = Reauthenticator(client, s, [ME])
        api.valid = set()
        assert client.request("GET", f"{BASE}/x", headers=s.credentials("tok1", "a")).response.status_code == 401
        assert api.logins == 0

    # Logins are capped per account, so an API that rejects every new token can't cause a loop.
    def test_refreshes_are_capped(self):
        api = FakeAuthApi(issued=[f"t{i}" for i in range(10)])
        client, settings, _ = _refreshing(api)
        for _ in range(MAX_REFRESHES + 2):
            api.valid = set()  # every token dies at once
            client.request("GET", f"{BASE}/x", headers=settings.credentials(settings.token_a, "a"))
        assert api.logins == MAX_REFRESHES

    # A login that hands back the same token would only repeat the 401: stop asking.
    def test_same_token_again_stops(self):
        logins = []

        def handler(request):
            if request.url.path == "/login":
                logins.append(request)
                return httpx.Response(200, json={"token": "tok1"})
            return httpx.Response(401)

        s = Settings(base_url=BASE, allowlist=["localhost:8000"], token_a="tok1", user_a="alice", password_a="pw")
        client = _client(handler)
        client.reauthenticate = Reauthenticator(client, s, [ME])
        for _ in range(3):
            assert client.request("GET", f"{BASE}/x", headers=s.credentials("tok1", "a")).response.status_code == 401
        assert len(logins) == 1

    # Without a refresher (or with refresh=False), a 401 is returned as it is.
    def test_refresh_can_be_switched_off(self):
        api = FakeAuthApi()
        client, settings, _ = _refreshing(api)
        api.valid = set()
        ex = client.request("GET", f"{BASE}/x", headers=settings.credentials("tok1", "a"), refresh=False)
        assert ex.response.status_code == 401 and api.logins == 0


# ---------------------------------------------------------------------------------------------
# concurrent rate-limit bursts


LOGIN = Endpoint(path="/login", method="POST", operation_id="login")


class ParallelLimiter:
    """Allows any number of requests in a row, but answers 429 when two are in flight at once."""

    def __init__(self):
        self.in_flight = 0
        self.peak = 0
        self.lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            crowded = self.in_flight > 1
        time.sleep(0.05)  # long enough for parallel requests to overlap
        with self.lock:
            self.in_flight -= 1
        return httpx.Response(429) if crowded else httpx.Response(401)


class TestConcurrentBurst:
    # One at a time, a limiter that only counts parallel requests never fires: reported.
    def test_sequential_misses_a_parallel_limiter(self):
        api = ParallelLimiter()
        ctx = _ctx(api, burst=6)
        (finding,) = RateLimit().run(LOGIN, ctx)
        assert api.peak == 1 and "in a row" in finding.detail

    # With --concurrency, the same limiter is seen and the endpoint passes.
    def test_concurrent_burst_sees_it(self):
        api = ParallelLimiter()
        ctx = _ctx(api, burst=6, concurrency=3)
        assert list(RateLimit().run(LOGIN, ctx)) == []
        assert api.peak > 1 and ctx.outcomes[("rate-limit", "POST /login")] == (TESTED, "")

    # An unlimited endpoint is still reported, and the finding says how the burst was sent.
    def test_concurrent_finding(self):
        ctx = _ctx(lambda r: httpx.Response(401), burst=6, concurrency=3)
        (finding,) = RateLimit().run(LOGIN, ctx)
        assert "6 identical requests 3 at a time" in finding.detail
        assert ctx.client.requests_sent == 6

    # The request cap still holds when requests come from several threads.
    def test_request_cap_holds(self):
        s = Settings(base_url=BASE, allowlist=["localhost:8000"], burst=20, concurrency=5)
        client = HttpClient(Allowlist(s.allowlist), transport=httpx.MockTransport(lambda r: httpx.Response(401)), max_requests=7)
        from apifuzz.errors import RequestLimitError
        with pytest.raises(RequestLimitError):
            list(RateLimit().run(LOGIN, ScanContext(client, s)))
        assert client.requests_sent == 7

    @pytest.mark.parametrize("value", [0, 11])
    def test_bounds(self, value):
        with pytest.raises(ConfigError):
            resolve_settings(base_url=BASE, concurrency=value, env={})

    def test_from_env(self):
        assert resolve_settings(base_url=BASE, env={"APIFUZZ_CONCURRENCY": "4"}).concurrency == 4
        with pytest.raises(ConfigError):
            resolve_settings(base_url=BASE, env={"APIFUZZ_CONCURRENCY": "many"})


# The spec parser hands header parameters to the check as "header" parameters.
def test_header_parameters_reach_the_endpoint_model():
    spec = {
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "paths": {"/stock": {"get": {"parameters": [
            {"name": "X-Warehouse", "in": "header", "required": True, "schema": {"type": "string"}}
        ], "responses": {"200": {"description": "ok"}}}}},
    }
    (endpoint,) = build_endpoints(spec)
    assert endpoint.parameters == [Parameter(name="X-Warehouse", location="header", required=True, type="string")]


# A benign value that is not handled still means "not tested", with the kind of input named.
def test_unhandled_baseline_names_the_input():
    ctx = _ctx(lambda r: httpx.Response(503))
    assert list(Injection().run(STOCK, ctx)) == []
    status, reason = ctx.outcomes[("injection", "GET /stock")]
    assert status == NOT_TESTED and "header 'X-Warehouse'" in reason
