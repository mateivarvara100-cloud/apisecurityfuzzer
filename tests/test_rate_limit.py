"""The rate-limit check, against a fake network."""

import json

import httpx
import pytest

from apifuzz.checks.base import NOT_TESTED, TESTED, ScanContext
from apifuzz.checks.rate_limit import RateLimit, kind_of
from apifuzz.endpoint_model import Endpoint, Parameter, RequestField
from apifuzz.finding import Severity
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.settings import ConfigError, Settings, resolve_settings

LOGIN = Endpoint(
    path="/login",
    method="POST",
    request_fields=[RequestField(name="username", required=True, type="string"),
                    RequestField(name="password", required=True, type="string")],
)
SEARCH = Endpoint(
    path="/search", method="GET", parameters=[Parameter(name="q", location="query", required=True, type="string")]
)


def _ctx(handler, **settings) -> ScanContext:
    s = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], **settings)
    return ScanContext(HttpClient(Allowlist(s.allowlist), transport=httpx.MockTransport(handler)), s)


class TestWhichEndpoints:
    @pytest.mark.parametrize(
        "method, path, operation_id, expected",
        [
            ("POST", "/login", None, "login"),
            ("POST", "/api/v1/auth/token", None, "login"),
            ("POST", "/users/authenticate", None, "login"),
            ("POST", "/x", "userLogin", "login"),
            ("GET", "/search", None, "search"),
            ("GET", "/products", "searchProducts", "search"),
            ("GET", "/login", None, None),  # a login page, not a login attempt
            ("POST", "/search", None, None),
            ("POST", "/register", None, None),  # would create accounts: never burst
            ("POST", "/password/reset", None, None),  # would send e-mails: never burst
            ("POST", "/messages", "sendMessage", None),
            ("GET", "/orders/{id}", "getOrder", None),
            ("GET", "/tokens/{token}", None, None),  # "{token}" is a placeholder, not a word
        ],
    )
    def test_kind_of(self, method, path, operation_id, expected):
        assert kind_of(Endpoint(path=path, method=method, operation_id=operation_id)) == expected

    def test_other_endpoints_send_nothing(self):
        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(RateLimit().run(Endpoint(path="/orders", method="POST"), ctx)) == []
        assert ctx.outcomes == {}  # not applicable


class TestRateLimit:
    # A login that accepts the whole burst with no sign of throttling is HIGH.
    def test_unlimited_login_is_high(self):
        bodies = []

        def handler(request):
            bodies.append(json.loads(request.content))
            return httpx.Response(401, json={"error": "bad credentials"})

        (finding,) = RateLimit().run(LOGIN, _ctx(handler))

        assert finding.severity is Severity.HIGH and finding.owasp.startswith("API4:2023")
        assert "15 identical requests" in finding.detail
        assert len(bodies) == 15 and len(finding.evidence) == 2  # first and last of the burst
        # Every attempt is a failed login for a user that doesn't exist: nothing real is touched.
        assert bodies[0] == {"username": "apifuzz-rate-limit-probe", "password": "apifuzz-rate-limit-probe"}

    # An unlimited search endpoint is MEDIUM, and gets a harmless value for its required parameter.
    def test_unlimited_search_is_medium(self):
        urls = []

        def handler(request):
            urls.append(str(request.url))
            return httpx.Response(200, json=[])

        (finding,) = RateLimit().run(SEARCH, _ctx(handler, burst=4))

        assert finding.severity is Severity.MEDIUM
        assert urls == ["http://localhost:8000/search?q=test"] * 4

    # A 429 part-way through means the endpoint is limited: no finding, and the burst stops there.
    def test_429_stops_the_burst(self):
        count = {"n": 0}

        def handler(request):
            count["n"] += 1
            return httpx.Response(429 if count["n"] > 5 else 401)

        ctx = _ctx(handler)
        assert list(RateLimit().run(LOGIN, ctx)) == []
        assert count["n"] == 6
        assert ctx.outcomes[("rate-limit", "POST /login")][0] == TESTED

    # Rate-limit headers count as throttling even while requests are still accepted.
    @pytest.mark.parametrize("header", ["RateLimit-Remaining", "X-RateLimit-Limit", "X-Rate-Limit-Remaining", "Retry-After"])
    def test_rate_limit_headers_count(self, header):
        sent = []
        ctx = _ctx(lambda r: sent.append(r) or httpx.Response(200, headers={header: "10"}, json=[]))
        assert list(RateLimit().run(SEARCH, ctx)) == []
        assert len(sent) == 1

    # A 404 or 5xx says the probe was wrong or the route is broken: not tested, with the reason.
    @pytest.mark.parametrize("status", [404, 405, 500, 503])
    def test_unhandled_answers_settle_nothing(self, status):
        ctx = _ctx(lambda r: httpx.Response(status))
        assert list(RateLimit().run(LOGIN, ctx)) == []
        outcome, reason = ctx.outcomes[("rate-limit", "POST /login")]
        assert outcome == NOT_TESTED and f"HTTP {status}" in reason

    # A protected search endpoint is called as a test account, or skipped (with a reason) without one.
    def test_protected_endpoint_uses_an_account(self):
        protected = SEARCH.model_copy(update={"requires_auth": True})
        seen = []
        ctx = _ctx(lambda r: seen.append(r.headers.get("authorization")) or httpx.Response(429), token_a="aaa")
        list(RateLimit().run(protected, ctx))
        assert seen == ["Bearer aaa"]

        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(RateLimit().run(protected, ctx)) == []
        assert ctx.outcomes[("rate-limit", "GET /search")] == (NOT_TESTED, "needs a test account")


class TestBurstSetting:
    def test_default_env_and_flag(self):
        assert resolve_settings(base_url="http://x", env={}).burst == 15
        assert resolve_settings(base_url="http://x", env={"APIFUZZ_BURST": "30"}).burst == 30
        assert resolve_settings(base_url="http://x", env={"APIFUZZ_BURST": "30"}, burst=5).burst == 5

    # The burst is capped so the check can never be turned into a load test.
    @pytest.mark.parametrize("value", ["1", "51", "1000", "many"])
    def test_out_of_range_is_refused(self, value):
        with pytest.raises(ConfigError):
            resolve_settings(base_url="http://x", env={"APIFUZZ_BURST": value})


class TestSlowdown:
    # An API that delays repeated attempts instead of refusing them is throttling too.
    def test_growing_delay_counts_as_throttling(self, monkeypatch):
        from apifuzz.checks import rate_limit

        assert rate_limit._slowed_down([10.0] * 5 + [50.0] * 5 + [900.0] * 5)
        assert not rate_limit._slowed_down([10.0] * 5 + [12.0] * 5 + [45.0] * 5)  # 4x, but only 35 ms: jitter
        assert not rate_limit._slowed_down([400.0] * 5 + [450.0] * 5 + [950.0] * 5)  # slow all along
        assert not rate_limit._slowed_down([10.0, 900.0])  # too short to say

        monkeypatch.setattr(rate_limit, "_slowed_down", lambda timings: True)
        ctx = _ctx(lambda r: httpx.Response(401))
        assert list(RateLimit().run(LOGIN, ctx)) == []
        assert ctx.outcomes[("rate-limit", "POST /login")][0] == TESTED
