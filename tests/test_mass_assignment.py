"""The mass-assignment check, against a fake API that keeps one user record in memory."""

import json

import httpx
import pytest

from apifuzz.checks.base import NOT_TESTED, TESTED, ScanContext
from apifuzz.checks.mass_assignment import PROBE_TEXT, MassAssignment
from apifuzz.endpoint_model import Endpoint, Parameter, RequestField
from apifuzz.finding import Severity
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.settings import Settings

ID = Parameter(name="id", location="path", required=True, type="integer")
FIELDS = [RequestField(name="name", type="string"), RequestField(name="email", type="string")]
ME = Endpoint(path="/me", method="GET", requires_auth=True)
GET_USER = Endpoint(path="/users/{id}", method="GET", requires_auth=True, parameters=[ID])
PATCH_USER = Endpoint(path="/users/{id}", method="PATCH", requires_auth=True, parameters=[ID], request_fields=FIELDS)
ALL = [ME, GET_USER, PATCH_USER]
KEY = ("mass-assignment", "PATCH /users/{id}")


class FakeUsers:
    """PATCH/PUT /users/7 and GET /users/7 over one stored record. `binds` decides what is saved."""

    def __init__(self, binds="everything", record=None):
        self.user = record or {"id": 7, "name": "Al", "email": "al@x.test", "role": "user", "credits": 10, "vip": False}
        self.binds = binds
        self.writes: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != "Bearer aaa":
            return httpx.Response(401)
        if request.url.path == "/me":
            return httpx.Response(200, json={"id": 7})
        if request.url.path != "/users/7":
            return httpx.Response(404)
        if request.method == "GET":
            return httpx.Response(200, json=self.user)
        body = json.loads(request.content)
        self.writes.append(body)
        if self.binds == "reject" and set(body) - {"name", "email"}:
            return httpx.Response(400, json={"error": "unknown field"})
        allowed = body if self.binds == "everything" else {k: v for k, v in body.items() if k in ("name", "email")}
        self.user.update(allowed)
        return httpx.Response(200, json=self.user)


def _ctx(handler, endpoints=ALL, token_a="aaa") -> ScanContext:
    s = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], token_a=token_a)
    return ScanContext(HttpClient(Allowlist(s.allowlist), transport=httpx.MockTransport(handler)), s, list(endpoints))


class TestMassAssignment:
    # An API that saves the whole body: each undeclared field that sticks is a finding, the
    # privilege field first and CRITICAL, and every original value is put back.
    def test_binding_everything_is_found_and_undone(self):
        api = FakeUsers()
        original = dict(api.user)
        findings = list(MassAssignment().run(PATCH_USER, _ctx(api)))

        assert [(f.key, f.severity) for f in findings] == [
            ("role", Severity.CRITICAL), ("credits", Severity.HIGH), ("vip", Severity.HIGH),
        ]
        assert api.user == original  # nothing is left changed on the target
        assert all("put back afterwards" in f.detail for f in findings)
        assert len({f.fingerprint for f in findings}) == 3  # one fingerprint per field
        assert findings[0].owasp.startswith("API3:2023")
        assert [e.request.method for e in findings[0].evidence] == ["PATCH", "GET", "PATCH"]

    # The probe proves the flaw without using it: the role is never set to a real one.
    def test_probe_values_grant_nothing(self):
        api = FakeUsers()
        list(MassAssignment().run(PATCH_USER, _ctx(api)))

        probes = [w for w in api.writes[::2]]  # every other write is a restore
        assert probes == [{"role": PROBE_TEXT}, {"credits": 11}, {"vip": True}]
        assert all(len(w) == 1 for w in api.writes)  # one field per request
        assert not any("id" in w or "name" in w for w in api.writes)  # declared fields and ids are left alone

    # An API that ignores undeclared fields, or rejects them, is clean, and counts as tested.
    @pytest.mark.parametrize("binds", ["declared-only", "reject"])
    def test_correct_api_is_clean(self, binds):
        api = FakeUsers(binds=binds)
        original = dict(api.user)
        ctx = _ctx(api)

        assert list(MassAssignment().run(PATCH_USER, ctx)) == []
        assert ctx.outcomes[KEY][0] == TESTED
        assert api.user == original

    # When no real field sticks, a few common hidden names are tried; one that is saved is reported.
    def test_hidden_field_is_guessed(self):
        api = FakeUsers(record={"id": 7, "name": "Al", "email": "al@x.test"})
        (finding, *rest) = MassAssignment().run(PATCH_USER, _ctx(api))

        assert finding.key == "role" and finding.severity is Severity.CRITICAL
        assert "did not exist" in finding.detail
        assert api.user.get("role") is None  # set back to nothing
        assert {f.key for f in rest} <= {"is_admin", "verified"}

    # Ids, owners, timestamps and secrets are never written to: that could not be undone safely.
    def test_untouchable_fields_are_left_alone(self):
        record = {"id": 7, "name": "Al", "owner_id": 3, "user": 3, "created_at": "2026-01-01", "password_hash": "x", "apiKey": "k"}
        api = FakeUsers(binds="declared-only", record=record)
        list(MassAssignment().run(PATCH_USER, _ctx(api)))

        assert [list(w) for w in api.writes] == [["role"], ["is_admin"], ["verified"]]  # only the hidden guesses

    # If the original value can't be put back, the finding says so plainly.
    def test_failed_restore_is_reported(self):
        api = FakeUsers()

        def sticky(request):
            if request.method == "PATCH" and json.loads(request.content) == {"role": "user"}:
                return httpx.Response(500)  # the restore fails
            return api(request)

        finding = next(iter(MassAssignment().run(PATCH_USER, _ctx(sticky))))

        assert finding.key == "role" and "could NOT be put back" in finding.detail

    # PUT replaces the object, so the current object is sent back whole with the one extra field.
    def test_put_sends_the_whole_object(self):
        put = PATCH_USER.model_copy(update={"method": "PUT"})
        api = FakeUsers(record={"id": 7, "name": "Al", "role": "user"})
        (finding,) = MassAssignment().run(put, _ctx(api, endpoints=[ME, GET_USER, put]))

        assert finding.key == "role"
        assert api.writes[0] == {"id": 7, "name": "Al", "role": PROBE_TEXT}
        assert api.user == {"id": 7, "name": "Al", "role": "user"}

    # A value that shows up once but not on the confirming read is not reported.
    def test_flaky_readback_is_not_reported(self):
        api = FakeUsers(record={"id": 7, "name": "Al", "role": "user"})
        reads = {"n": 0}

        def handler(request):
            if request.method == "GET" and request.url.path == "/users/7":
                reads["n"] += 1
                if reads["n"] == 3:  # the confirming read after the first probe
                    return httpx.Response(200, json={"id": 7, "name": "Al", "role": "user"})
            return api(request)

        assert not any(f.key == "role" for f in MassAssignment().run(PATCH_USER, _ctx(handler)))


class TestWhenItCannotRun:
    @pytest.mark.parametrize(
        "endpoint, endpoints, token, reason",
        [
            (PATCH_USER, ALL, None, "needs a test account"),
            (PATCH_USER, [ME, PATCH_USER], "aaa", "no GET on the same path"),
            (PATCH_USER, [GET_USER, PATCH_USER], "aaa", "no object of the test account"),
            (Endpoint(path="/orders", method="POST", requires_auth=True, request_fields=FIELDS), ALL, "aaa", "no DELETE and GET"),
        ],
    )
    def test_reason_is_recorded(self, endpoint, endpoints, token, reason):
        ctx = _ctx(FakeUsers(), endpoints=endpoints, token_a=token)
        assert list(MassAssignment().run(endpoint, ctx)) == []
        outcome, why = ctx.outcomes[("mass-assignment", f"{endpoint.method} {endpoint.path}")]
        assert outcome == NOT_TESTED and reason in why

    # Endpoints without a body, without a login, or that only read are not this check's business.
    @pytest.mark.parametrize(
        "endpoint",
        [
            GET_USER,
            PATCH_USER.model_copy(update={"requires_auth": False}),
            PATCH_USER.model_copy(update={"request_fields": []}),
            Endpoint(path="/users/{id}", method="DELETE", requires_auth=True, parameters=[ID]),
        ],
    )
    def test_not_applicable_sends_nothing(self, endpoint):
        ctx = _ctx(lambda r: pytest.fail("sent a request"))
        assert list(MassAssignment().run(endpoint, ctx)) == []
        assert ctx.outcomes == {}

    # The object id comes from the caller's own listing when the collection has one.
    def test_own_object_from_a_listing(self):
        orders = Endpoint(path="/orders", method="GET", requires_auth=True)
        get_order = Endpoint(path="/orders/{id}", method="GET", requires_auth=True, parameters=[ID])
        patch_order = get_order.model_copy(update={"method": "PATCH", "request_fields": [RequestField(name="note", type="string")]})
        order = {"id": 42, "note": "x", "status": "new"}
        written = []

        def handler(request):
            if request.url.path == "/orders":
                return httpx.Response(200, json=[{"id": 42}])
            if request.url.path == "/orders/42":
                if request.method == "PATCH":
                    written.append(json.loads(request.content))
                return httpx.Response(200, json=order)
            return httpx.Response(404)

        assert list(MassAssignment().run(patch_order, _ctx(handler, endpoints=[orders, get_order, patch_order]))) == []
        assert written[0] == {"status": PROBE_TEXT}


class FakeOrders:
    """POST /orders, GET and DELETE /orders/{id}. `binds` decides whether extra fields are saved."""

    def __init__(self, binds="everything", can_delete=True):
        self.orders: dict[int, dict] = {}
        self.binds, self.can_delete = binds, can_delete
        self.created: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != "Bearer aaa":
            return httpx.Response(401)
        if request.method == "POST" and request.url.path == "/orders":
            body = json.loads(request.content)
            self.created.append(body)
            oid = 100 + len(self.created)
            order = {"id": oid, "item": body.get("item"), "status": "new", "paid": False}
            if self.binds == "everything":
                order.update({k: v for k, v in body.items() if k != "id"})
            self.orders[oid] = order
            return httpx.Response(201, json=order)
        oid = int(request.url.path.rsplit("/", 1)[1])
        if oid not in self.orders:
            return httpx.Response(404)
        if request.method == "DELETE":
            if not self.can_delete:
                return httpx.Response(500)
            del self.orders[oid]
            return httpx.Response(204)
        return httpx.Response(200, json=self.orders[oid])


CREATE = Endpoint(path="/orders", method="POST", requires_auth=True,
                  request_fields=[RequestField(name="item", required=True, type="string")])
GET_ORDER = Endpoint(path="/orders/{id}", method="GET", requires_auth=True, parameters=[ID])
DELETE_ORDER = Endpoint(path="/orders/{id}", method="DELETE", requires_auth=True, parameters=[ID])
ORDER_API = [CREATE, GET_ORDER, DELETE_ORDER]


class TestCreateEndpoints:
    # A create endpoint that saves extra fields is found, and every object made for the test is deleted.
    def test_binding_on_create_is_found_and_cleaned_up(self):
        api = FakeOrders()
        findings = list(MassAssignment().run(CREATE, _ctx(api, endpoints=ORDER_API)))

        assert [(f.key, f.severity) for f in findings] == [("status", Severity.HIGH), ("paid", Severity.HIGH), ("role", Severity.CRITICAL)]
        assert api.orders == {}  # nothing left behind
        assert all("deleted again" in f.detail for f in findings)
        assert api.created == [
            {"item": "test"}, {"item": "test", "status": PROBE_TEXT}, {"item": "test", "paid": True}, {"item": "test", "role": PROBE_TEXT},
        ]
        assert [e.request.method for e in findings[0].evidence] == ["POST", "GET", "DELETE"]

    def test_correct_create_is_clean(self):
        api = FakeOrders(binds="declared-only")
        ctx = _ctx(api, endpoints=ORDER_API)
        assert list(MassAssignment().run(CREATE, ctx)) == []
        assert ctx.outcomes[("mass-assignment", "POST /orders")][0] == TESTED and api.orders == {}

    # Without a DELETE in the spec nothing is created at all.
    def test_no_delete_means_no_create(self):
        ctx = _ctx(lambda r: pytest.fail("sent a request"), endpoints=[CREATE, GET_ORDER])
        assert list(MassAssignment().run(CREATE, ctx)) == []
        assert "could not be cleaned up" in ctx.outcomes[("mass-assignment", "POST /orders")][1]

    # If a delete fails, the report names the objects left on the target.
    def test_failed_cleanup_is_reported(self):
        from apifuzz.checks import select_checks
        from apifuzz.scanner import run_scan

        api = FakeOrders(can_delete=False)
        result = run_scan(ORDER_API, select_checks(only=["mass-assignment"]), _ctx(api, endpoints=ORDER_API))

        assert any("left behind on the target" in line and "101" in line for line in result.errors)
        assert all("could NOT be deleted" in f.detail for f in result.findings)
