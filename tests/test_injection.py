"""The injection check, against a fake network.

Each test wires the check to a small handler that stands in for an API, so the detection logic
(error-based and boolean-differential, with a confirmation request) can be exercised without a
real database. The end-to-end proof against the real SQLite-backed lab lives in
test_phase1_complete.py.
"""

import json

import httpx
import pytest

from apifuzz.checks.base import NOT_TESTED, TESTED, ScanContext
from apifuzz.checks.injection import Injection
from apifuzz.endpoint_model import Endpoint, Parameter, RequestField
from apifuzz.finding import Severity
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.settings import Settings

SEARCH = Endpoint(
    path="/search", method="GET", parameters=[Parameter(name="q", location="query", required=True, type="string")]
)
LOGIN = Endpoint(
    path="/login", method="POST", operation_id="login",
    request_fields=[RequestField(name="username", required=True, type="string"),
                    RequestField(name="password", required=True, type="string")],
)


def _ctx(handler, **settings) -> ScanContext:
    s = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], **settings)
    return ScanContext(HttpClient(Allowlist(s.allowlist), transport=httpx.MockTransport(handler)), s)


def _q(request: httpx.Request) -> str:
    return request.url.params.get("q", "")


PRODUCTS = ["book", "lamp", "mug", "pen"]


# A handler that stands in for `WHERE name LIKE '%<q>%'` with the value pasted into the query: the
# lone-quote probe surfaces a database error, and the always-true clause matches every row while
# the always-false clause matches none. It keys off the exact payloads the check sends, so the
# test pins the decision logic; the real SQL behaviour is proven against the lab in
# test_phase1_complete.py.
def vulnerable(request: httpx.Request) -> httpx.Response:
    q = _q(request)
    if q == "apifuzz'":  # the unbalanced quote breaks the string literal
        return httpx.Response(500, json={"error": "SQL error: unrecognized token near \"'\""})
    if "OR '1'='1'" in q:  # the always-true clause matches every row
        return httpx.Response(200, json=PRODUCTS)
    if "AND '1'='2'" in q:  # the always-false clause matches none
        return httpx.Response(200, json=[])
    return httpx.Response(200, json=[p for p in PRODUCTS if q in p])


# A handler that treats the value as plain text: the markers are searched for literally, so every
# probe comes back the same way and nothing should be reported.
def safe(request: httpx.Request) -> httpx.Response:
    q = _q(request)
    return httpx.Response(200, json=[p for p in PRODUCTS if q in p])


class TestDetection:
    # An unbalanced quote that surfaces a database error is reported, with evidence.
    def test_error_based_is_found(self):
        ctx = _ctx(vulnerable)
        findings = list(Injection().run(SEARCH, ctx))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity is Severity.HIGH and f.key == "q"
        assert f.owasp.startswith("API8") and "database error" in f.detail
        assert ctx.outcomes[("injection", "GET /search")] == (TESTED, "")

    # When no quote error surfaces, the always-true/always-false result-set difference is used.
    def test_boolean_differential_is_found(self):
        # Like `vulnerable`, but a quote is swallowed instead of erroring, so only the boolean
        # signal is available.
        def no_error(request):
            r = vulnerable(request)
            return httpx.Response(200, json=[]) if r.status_code == 500 else r

        findings = list(Injection().run(SEARCH, _ctx(no_error)))
        assert len(findings) == 1 and "boolean differential" in findings[0].detail

    # An endpoint that treats input as plain text is clean (no false positive).
    def test_safe_endpoint_is_clean(self):
        ctx = _ctx(safe)
        assert list(Injection().run(SEARCH, ctx)) == []
        assert ctx.outcomes[("injection", "GET /search")] == (TESTED, "")

    # An endpoint that merely echoes the payload back (different bodies, same shape) is not flagged.
    def test_echo_is_not_a_differential(self):
        def echo(request):
            return httpx.Response(200, json={"you_sent": _q(request)})

        assert list(Injection().run(SEARCH, _ctx(echo))) == []

    # A one-off difference that doesn't repeat is not reported.
    def test_flaky_difference_is_not_reported(self):
        seen = {"n": 0}

        def flaky(request):
            if _q(request) == "apifuzz'":
                return httpx.Response(200, json=[])  # no database error to go on
            seen["n"] += 1
            # Differ once, then stop differing on the confirmation pair.
            size = 3 if seen["n"] == 1 else 0
            return httpx.Response(200, json=list(range(size)))

        assert list(Injection().run(SEARCH, _ctx(flaky))) == []


def _field(request: httpx.Request, name: str):
    try:
        return json.loads(request.content).get(name)
    except (ValueError, AttributeError):
        return None


class TestBodyFields:
    # A login whose username lookup errors on a lone quote is found (error-based), keyed to the field.
    def test_body_field_error_based_is_found(self):
        def login(request):
            if _field(request, "username") == "apifuzz'":
                return httpx.Response(500, json={"error": "SQL error: unrecognized token"})
            return httpx.Response(401, json={"error": "bad credentials"})

        ctx = _ctx(login)
        findings = list(Injection().run(LOGIN, ctx))
        assert [f.key for f in findings] == ["username"]  # only the injectable field, not password
        assert findings[0].severity is Severity.HIGH and "body field" in findings[0].title.lower()
        assert ctx.outcomes[("injection", "POST /login")] == (TESTED, "")

    # An operator object accepted where a scalar is expected is reported as NoSQL injection.
    def test_nosql_operator_object_is_found(self):
        docs = ["a", "b", "c"]

        def mongo(request):
            u = _field(request, "username")
            if isinstance(u, dict):  # the operator object is honoured: every document matches
                return httpx.Response(200, json=docs)
            return httpx.Response(200, json=[d for d in docs if d == u])

        findings = list(Injection().run(LOGIN, _ctx(mongo)))
        assert len(findings) == 1 and findings[0].key == "username"
        assert "NoSQL operator" in findings[0].detail

    # A login that treats input as plain text is clean.
    def test_safe_login_is_clean(self):
        ctx = _ctx(lambda r: httpx.Response(401, json={"error": "bad credentials"}))
        assert list(Injection().run(LOGIN, ctx)) == []
        assert ctx.outcomes[("injection", "POST /login")] == (TESTED, "")

    # Body fields are only probed on read/auth-shaped endpoints, never on data-creating ones.
    def test_create_endpoint_body_is_not_probed(self):
        create = Endpoint(
            path="/orders", method="POST", operation_id="createOrder",
            request_fields=[RequestField(name="item", required=True, type="string")],
        )
        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(Injection().run(create, ctx)) == []
        assert ctx.outcomes == {}


class TestScope:
    # Endpoints with no query parameter are not applicable: nothing is sent, nothing recorded.
    def test_no_query_param_is_not_applicable(self):
        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(Injection().run(Endpoint(path="/me", method="GET"), ctx)) == []
        assert ctx.outcomes == {}

    # Writing methods are left alone, so the check can't create or change data.
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_writing_methods_are_skipped(self, method):
        ep = Endpoint(path="/search", method=method, parameters=[Parameter(name="q", location="query", type="string")])
        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(Injection().run(ep, ctx)) == []
        assert ctx.outcomes == {}

    # A protected endpoint with no test account is recorded as not tested, not silently skipped.
    def test_protected_endpoint_needs_an_account(self):
        ep = Endpoint(
            path="/search", method="GET", requires_auth=True,
            parameters=[Parameter(name="q", location="query", required=True, type="string")],
        )
        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(Injection().run(ep, ctx)) == []
        assert ctx.outcomes[("injection", "GET /search")] == (NOT_TESTED, "needs a test account")

    # If a benign value is not even handled (a 404 for the sample), there's no baseline: not tested.
    def test_unhandled_baseline_is_not_tested(self):
        ctx = _ctx(lambda r: httpx.Response(404, json={"error": "no"}))
        assert list(Injection().run(SEARCH, ctx)) == []
        status, reason = ctx.outcomes[("injection", "GET /search")]
        assert status == NOT_TESTED and "not handled" in reason
