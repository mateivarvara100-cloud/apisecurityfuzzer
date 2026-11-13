"""The bola check, against a fake network."""

import httpx
import pytest

from apifuzz.checks.base import NOT_TESTED, TESTED, ScanContext
from apifuzz.checks.bola import Bola
from apifuzz.endpoint_model import Endpoint, Parameter
from apifuzz.finding import Severity
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.settings import Settings

A, B = "Bearer aaa", "Bearer bbb"
ME = Endpoint(path="/me", method="GET", requires_auth=True)
ORDERS = Endpoint(path="/orders", method="GET", requires_auth=True)


def _endpoint(method="GET", requires_auth=True, ptype="integer", extra=(), path="/orders/{id}") -> Endpoint:
    params = [Parameter(name="id", location="path", required=True, type=ptype), *extra]
    return Endpoint(path=path, method=method, requires_auth=requires_auth, parameters=params)


def _ctx(handler, token_a="aaa", token_b="bbb", endpoints=(), **settings) -> ScanContext:
    s = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], token_a=token_a, token_b=token_b, **settings)
    client = HttpClient(Allowlist(s.allowlist), transport=httpx.MockTransport(handler))
    return ScanContext(client, s, list(endpoints))


def _api(*, owner_check: bool, login_check: bool = True, body=None, listing: bool = False):
    """A fake orders API. Order 1 belongs to A, order 2 to B; ids above 2 don't exist.

    With `listing`, GET /orders returns the caller's own order ids (a real "my orders" page).
    """
    owners = {"/orders/1": A, "/orders/2": B}

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization")
        if login_check and auth not in (A, B):
            return httpx.Response(401)
        if listing and request.url.path == "/orders":
            return httpx.Response(200, json=[{"id": 1 if auth == A else 2}])
        owner = owners.get(request.url.path)
        if owner is None:
            return httpx.Response(404)
        if owner_check and auth != owner:
            return httpx.Response(403)
        return httpx.Response(200, json=body if body is not None else {"id": 1, "owner": 1})

    return handler


class TestBola:
    # No ownership check, and the order is listed only in A's own orders: proven, CRITICAL.
    def test_cross_user_read_is_critical(self):
        ctx = _ctx(_api(owner_check=False, listing=True, body={"id": 1, "item": "book"}), endpoints=[ORDERS])
        (finding,) = Bola().run(_endpoint(), ctx)

        assert finding.severity is Severity.CRITICAL
        assert finding.endpoint == "GET /orders/{id}"
        assert "lists this id only for account A" in finding.detail
        assert finding.remediation
        sent = [e.request.headers.get("authorization") for e in finding.evidence]
        assert sent == [A, B, None, B]  # as A, as B, anonymous (refused), confirmation as B
        assert finding.evidence[2].response.status_code == 401

    # An owner field alone is a strong hint, not proof (a public post names its author): HIGH.
    def test_owner_field_alone_is_high(self):
        (finding,) = Bola().run(_endpoint(), _ctx(_api(owner_check=False)))

        assert finding.severity is Severity.HIGH
        assert "not proof" in finding.detail and "--shared" in finding.detail

    # Without any sign of ownership the object might be shared on purpose: LOW, and it says so.
    def test_unproven_ownership_is_low(self):
        (finding,) = Bola().run(_endpoint(), _ctx(_api(owner_check=False, body={"id": 1, "item": "book"})))

        assert finding.severity is Severity.LOW
        assert "shared" in finding.detail and "not proven" in finding.title

    # An API that enforces ownership produces no finding, and counts as tested.
    def test_correct_api_is_clean(self):
        ctx = _ctx(_api(owner_check=True))
        assert list(Bola().run(_endpoint(), ctx)) == []
        assert ctx.outcomes[("bola", "GET /orders/{id}")][0] == TESTED

    # Open to anonymous callers too: that's auth-required's finding, not BOLA.
    def test_unauthenticated_endpoint_is_left_to_auth_required(self):
        assert list(Bola().run(_endpoint(), _ctx(_api(owner_check=False, login_check=False)))) == []

    # A result that doesn't reproduce on the confirmation request is not reported.
    def test_flaky_result_is_not_reported(self):
        calls = {"b": 0}

        def handler(request):
            auth = request.headers.get("authorization")
            if auth is None:
                return httpx.Response(401)
            if auth == B:
                calls["b"] += 1
                if calls["b"] % 2 == 0:  # every second request as B fails
                    return httpx.Response(403)
            return httpx.Response(200, json={"id": 1})

        assert list(Bola().run(_endpoint(), _ctx(handler))) == []

    # Nothing readable by either account means nothing was compared: "not tested", with a reason.
    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_failures_are_not_findings(self, status):
        ctx = _ctx(lambda r: httpx.Response(status))
        assert list(Bola().run(_endpoint(), ctx)) == []
        outcome, reason = ctx.outcomes[("bola", "GET /orders/{id}")]
        assert outcome == NOT_TESTED and "neither account could read" in reason

    # Without both tokens, or for endpoints it can't probe safely, nothing is sent.
    @pytest.mark.parametrize(
        "endpoint, ctx_kwargs",
        [
            (_endpoint(), {"token_b": None}),
            (_endpoint(), {"token_a": None}),
            (_endpoint(method="DELETE"), {}),
            (_endpoint(method="PATCH"), {}),
            (_endpoint(requires_auth=False), {}),
            (_endpoint(ptype="string"), {}),  # no real id known, and string ids can't be guessed
            (_endpoint(extra=[Parameter(name="x", location="path", required=True, type="integer")]), {}),
            (_endpoint(), {"shared_paths": ["/orders/*"]}),
        ],
    )
    def test_skipped_cases_send_nothing(self, endpoint, ctx_kwargs):
        sent = []
        ctx = _ctx(lambda r: sent.append(r) or httpx.Response(200), **ctx_kwargs)
        assert list(Bola().run(endpoint, ctx)) == []
        assert sent == []

    # An endpoint the check applies to but skips is recorded with the reason, never silently.
    @pytest.mark.parametrize(
        "endpoint, ctx_kwargs, reason",
        [
            (_endpoint(), {"token_b": None}, "two test accounts"),
            (_endpoint(ptype="string"), {}, "no real id"),
            (_endpoint(extra=[Parameter(name="x", location="path", required=True, type="integer")]), {}, "no id of test account A"),
            (_endpoint(), {"shared_paths": ["/orders/*"]}, "--shared"),
        ],
    )
    def test_skips_are_recorded_with_a_reason(self, endpoint, ctx_kwargs, reason):
        ctx = _ctx(lambda r: httpx.Response(200), **ctx_kwargs)
        list(Bola().run(endpoint, ctx))
        outcome, why = ctx.outcomes[("bola", "GET /orders/{id}")]
        assert outcome == NOT_TESTED and reason in why


class TestFalsePositives:
    """Cases from the Phase 1 review where a correct or harmless API used to get a CRITICAL."""

    # A 200 that carries an error message for the wrong user is not a leak: bodies are compared.
    def test_200_with_an_error_body_is_not_a_finding(self):
        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path != "/orders/1":
                return httpx.Response(404)
            return httpx.Response(200, json={"id": 1, "owner": 1} if auth == A else {"error": "forbidden"})

        ctx = _ctx(handler)
        assert list(Bola().run(_endpoint(), ctx)) == []
        assert ctx.outcomes[("bola", "GET /orders/{id}")][0] == TESTED

    # A user id from /me says nothing about who owns product 7: ids are attributed per collection.
    def test_ids_from_another_resource_prove_nothing(self):
        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/me":
                return httpx.Response(200, json={"id": 7 if auth == A else 8})
            return httpx.Response(200, json={"sku": "book"}) if request.url.path == "/products/7" else httpx.Response(404)

        (finding,) = Bola().run(_endpoint(path="/products/{id}"), _ctx(handler, endpoints=[ME]))

        assert finding.severity is Severity.LOW  # readable by both, but nothing proves an owner

    # An object the API itself lists to both accounts is shared by design: no finding at all.
    def test_object_listed_to_both_accounts_is_shared(self):
        products = Endpoint(path="/products", method="GET", requires_auth=True)

        def handler(request):
            if request.headers.get("authorization") not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/products":
                return httpx.Response(200, json=[{"id": 1, "name": "book"}])
            return httpx.Response(200, json={"id": 1, "name": "book"}) if request.url.path == "/products/1" else httpx.Response(404)

        ctx = _ctx(handler, endpoints=[products])
        assert list(Bola().run(_endpoint(path="/products/{id}"), ctx)) == []
        assert ctx.outcomes[("bola", "GET /products/{id}")][0] == TESTED

    # If one account's listing could not be read, "only the other lists it" can't be claimed.
    def test_a_missing_listing_proves_nothing(self):
        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/orders":
                return httpx.Response(200, json=[{"id": 1}]) if auth == A else httpx.Response(500)
            return httpx.Response(200, json={"id": 1, "item": "book"}) if request.url.path == "/orders/1" else httpx.Response(404)

        (finding,) = Bola().run(_endpoint(), _ctx(handler, endpoints=[ORDERS]))

        assert finding.severity is Severity.LOW


class TestRecon:
    # Real ids are learned from the accounts' own parameterless GETs (here /me), so an object
    # with an id far outside 1-5 is still found.
    def test_harvested_id_is_probed(self):
        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/me":
                return httpx.Response(200, json={"user": {"id": 7}, "orders": [{"order_id": 1042}]})
            if request.url.path == "/orders/1042":
                return httpx.Response(200, json={"id": 1042, "owner": 7})
            return httpx.Response(404)

        ctx = _ctx(handler, endpoints=[ME, _endpoint()])
        (finding,) = Bola().run(_endpoint(), ctx)

        assert finding.evidence[0].request.url.endswith("/orders/1042")
        assert finding.owasp.startswith("API1:2023")

    # String ids such as UUIDs can't be guessed, but ids found by recon are probed like any other.
    def test_string_ids_from_recon_are_probed(self):
        ids = {A: "3f2a-aaaa", B: "9c1d-bbbb"}

        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/orders":
                return httpx.Response(200, json={"items": [{"id": ids[auth]}]})
            if request.url.path.removeprefix("/orders/") in ids.values():
                return httpx.Response(200, json={"id": request.url.path.removeprefix("/orders/"), "item": "book"})
            return httpx.Response(404)

        (finding,) = Bola().run(_endpoint(ptype="string"), _ctx(handler, endpoints=[ORDERS]))

        assert finding.severity is Severity.CRITICAL
        assert finding.evidence[0].request.url.endswith("/orders/3f2a-aaaa")

    # A string that isn't a plain id (spaces, slashes) is never put into a URL.
    def test_unsafe_strings_are_not_used_as_ids(self):
        sent = []

        def handler(request):
            sent.append(request.url.path)
            return httpx.Response(200, json=[{"id": "../admin"}, {"id": "a b"}])

        assert list(Bola().run(_endpoint(ptype="string"), _ctx(handler, endpoints=[ORDERS]))) == []
        assert sent == ["/orders", "/orders"]  # recon only

    # The login header comes from the settings, so an API-key scheme works the same way.
    def test_uses_the_configured_auth_header(self):
        seen = []

        def handler(request):
            seen.append(request.headers.get("x-api-key"))
            return httpx.Response(404)

        list(Bola().run(_endpoint(), _ctx(handler, auth_header="X-API-Key", auth_prefix="")))

        assert set(seen) == {"aaa", "bbb"}

    # Recon runs once per scan, not once per endpoint.
    def test_recon_is_cached(self):
        calls = []

        def handler(request):
            calls.append(request.url.path)
            return httpx.Response(404)

        ctx = _ctx(handler, endpoints=[ME])
        list(Bola().run(_endpoint(), ctx))
        list(Bola().run(_endpoint(), ctx))

        assert calls.count("/me") == 2  # once as A, once as B, then cached


class TestNestedPaths:
    """GET /users/{userId}/orders/{orderId}: the last id is probed under account A's own user id."""

    USER = Parameter(name="userId", location="path", required=True, type="integer")
    ORDER = Parameter(name="orderId", location="path", required=True, type="integer")
    LIST = Endpoint(path="/users/{userId}/orders", method="GET", requires_auth=True, parameters=[USER])
    ONE = Endpoint(path="/users/{userId}/orders/{orderId}", method="GET", requires_auth=True, parameters=[ORDER, USER])

    def _api(self, *, owner_check: bool):
        users = {A: 11, B: 22}

        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in users:
                return httpx.Response(401)
            path = request.url.path
            if path == "/me":
                return httpx.Response(200, json={"id": users[auth]})
            if not path.startswith("/users/11/orders"):
                return httpx.Response(404)
            if users[auth] != 11 and (owner_check or path == "/users/11/orders"):
                return httpx.Response(403)  # the listing is always protected; the object only if owner_check
            if path == "/users/11/orders":
                return httpx.Response(200, json=[{"id": 900}])
            return httpx.Response(200, json={"id": 900, "item": "book"}) if path.endswith("/900") else httpx.Response(404)

        return handler

    # B can read an order that only A's own listing shows: proven, CRITICAL.
    def test_cross_user_read_under_a_parent_id(self):
        ctx = _ctx(self._api(owner_check=False), endpoints=[ME, self.LIST, self.ONE])
        (finding,) = Bola().run(self.ONE, ctx)

        assert finding.severity is Severity.CRITICAL
        assert finding.evidence[0].request.url.endswith("/users/11/orders/900")
        assert "only for account A" in finding.detail

    def test_correct_nested_api_is_clean(self):
        ctx = _ctx(self._api(owner_check=True), endpoints=[ME, self.LIST, self.ONE])
        assert list(Bola().run(self.ONE, ctx)) == []
        assert ctx.outcomes[("bola", "GET /users/{userId}/orders/{orderId}")][0] == TESTED

    # Without a "who am I" answer, A's own user id is unknown and the endpoint is listed as not tested.
    def test_unknown_parent_id_is_not_tested(self):
        ctx = _ctx(self._api(owner_check=False), endpoints=[self.LIST, self.ONE])
        assert list(Bola().run(self.ONE, ctx)) == []
        outcome, reason = ctx.outcomes[("bola", "GET /users/{userId}/orders/{orderId}")]
        assert outcome == NOT_TESTED and "{userId}" in reason
