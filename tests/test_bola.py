"""The bola check, against a fake network."""

import httpx
import pytest

from apifuzz.checks.base import ScanContext
from apifuzz.checks.bola import Bola
from apifuzz.endpoint_model import Endpoint, Parameter
from apifuzz.finding import Severity
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.settings import Settings

A, B = "Bearer aaa", "Bearer bbb"


def _endpoint(method="GET", requires_auth=True, ptype="integer", extra=()) -> Endpoint:
    params = [Parameter(name="id", location="path", required=True, type=ptype), *extra]
    return Endpoint(path="/orders/{id}", method=method, requires_auth=requires_auth, parameters=params)


def _ctx(handler, token_a="aaa", token_b="bbb") -> ScanContext:
    settings = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], token_a=token_a, token_b=token_b)
    client = HttpClient(Allowlist(settings.allowlist), transport=httpx.MockTransport(handler))
    return ScanContext(client, settings)


def _api(*, owner_check: bool, login_check: bool = True, body=None):
    """A fake orders API. Order 1 belongs to A, order 2 to B; ids above 2 don't exist."""
    owners = {"/orders/1": A, "/orders/2": B}

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization")
        if login_check and auth not in (A, B):
            return httpx.Response(401)
        owner = owners.get(request.url.path)
        if owner is None:
            return httpx.Response(404)
        if owner_check and auth != owner:
            return httpx.Response(403)
        return httpx.Response(200, json=body if body is not None else {"id": 1, "owner": 1})

    return handler


class TestBola:
    # Logged in but no ownership check, and the object has an owner field: CRITICAL, with evidence.
    def test_cross_user_read_is_critical(self):
        (finding,) = Bola().run(_endpoint(), _ctx(_api(owner_check=False)))

        assert finding.severity is Severity.CRITICAL
        assert finding.endpoint == "GET /orders/{id}"
        assert finding.remediation
        sent = [e.request.headers.get("authorization") for e in finding.evidence]
        assert sent == [A, B, None, B]  # as A, as B, anonymous (refused), confirmation as B
        assert finding.evidence[2].response.status_code == 401

    # Without proof of ownership the object might be shared on purpose: LOW, and it says so.
    def test_unproven_ownership_is_low(self):
        (finding,) = Bola().run(_endpoint(), _ctx(_api(owner_check=False, body={"id": 1, "item": "book"})))

        assert finding.severity is Severity.LOW
        assert "shared" in finding.detail and "not proven" in finding.title

    # An API that enforces ownership produces no finding.
    def test_correct_api_is_clean(self):
        assert list(Bola().run(_endpoint(), _ctx(_api(owner_check=True)))) == []

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

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_failures_are_not_findings(self, status):
        assert list(Bola().run(_endpoint(), _ctx(lambda r: httpx.Response(status)))) == []

    # Without both tokens, or for endpoints it can't probe safely, nothing is sent.
    @pytest.mark.parametrize(
        "endpoint, ctx_kwargs",
        [
            (_endpoint(), {"token_b": None}),
            (_endpoint(), {"token_a": None}),
            (_endpoint(method="DELETE"), {}),
            (_endpoint(method="PATCH"), {}),
            (_endpoint(requires_auth=False), {}),
            (_endpoint(ptype="string"), {}),
            (_endpoint(extra=[Parameter(name="x", location="path", required=True, type="integer")]), {}),
        ],
    )
    def test_skipped_cases_send_nothing(self, endpoint, ctx_kwargs):
        sent = []
        ctx = _ctx(lambda r: sent.append(r) or httpx.Response(200), **ctx_kwargs)
        assert list(Bola().run(endpoint, ctx)) == []
        assert sent == []


class TestRecon:
    # Recon attributes ids to accounts: an id seen only in B's own data that A can read is proof
    # of ownership, even without an owner field in the object.
    def test_recon_attribution_proves_ownership(self):
        me = Endpoint(path="/me", method="GET", requires_auth=True)

        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/me":
                return httpx.Response(200, json={"id": 501 if auth == A else 502})
            if request.url.path in ("/orders/501", "/orders/502"):
                return httpx.Response(200, json={"item": "book"})  # no owner field
            return httpx.Response(404)

        ctx = _ctx(handler)
        ctx.endpoints = [me]
        (finding,) = Bola().run(_endpoint(), ctx)

        assert finding.severity is Severity.CRITICAL
        assert "only in account A's own data" in finding.detail

    # Real ids are learned from the accounts' own parameterless GETs (here /me), so an object
    # with an id far outside 1-5 is still found.
    def test_harvested_id_is_probed(self):
        me = Endpoint(path="/me", method="GET", requires_auth=True)

        def handler(request):
            auth = request.headers.get("authorization")
            if auth not in (A, B):
                return httpx.Response(401)
            if request.url.path == "/me":
                return httpx.Response(200, json={"user": {"id": 7}, "orders": [{"order_id": 1042}]})
            if request.url.path == "/orders/1042":
                return httpx.Response(200, json={"id": 1042, "owner": 7})
            return httpx.Response(404)

        ctx = _ctx(handler)
        ctx.endpoints = [me, _endpoint()]
        (finding,) = Bola().run(_endpoint(), ctx)

        assert finding.evidence[0].request.url.endswith("/orders/1042")
        assert finding.owasp.startswith("API1:2023")
        assert ctx.cache["bola_recon"] == ({7, 1042}, {7, 1042})

    # Recon runs once per scan, not once per endpoint.
    def test_recon_is_cached(self):
        me = Endpoint(path="/me", method="GET", requires_auth=True)
        calls = []

        def handler(request):
            calls.append(request.url.path)
            return httpx.Response(404)

        ctx = _ctx(handler)
        ctx.endpoints = [me]
        list(Bola().run(_endpoint(), ctx))
        list(Bola().run(_endpoint(), ctx))

        assert calls.count("/me") == 2  # once as A, once as B, then cached
