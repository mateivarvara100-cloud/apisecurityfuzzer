"""The HTTP API: who may do what, the refusals, the limits and who sees which scan."""

import threading
from datetime import timedelta

from apifuzz_web.app import _in_background
from apifuzz_web.engine import ScanFailed
from conftest import ALICE, LAB, auth, finished, scan_body, start, wait_for

_wait_for = wait_for

# ---- sign-in --------------------------------------------------------------------------------


def test_health_needs_no_sign_in_and_says_little(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert set(r.json()) == {"ok", "engine"}


def test_every_other_route_needs_a_sign_in(client):
    for method, path in [("get", "/me"), ("get", "/scans"), ("get", f"/scans/{ALICE.id}"), ("post", "/scans")]:
        r = getattr(client, method)(path, **({"json": scan_body()} if method == "post" else {}))
        assert r.status_code == 401, path
        assert r.headers["www-authenticate"] == "Bearer"


def test_a_bad_token_or_scheme_is_refused(client):
    assert client.get("/me", headers={"Authorization": "Bearer nobody"}).status_code == 401
    assert client.get("/me", headers={"Authorization": "Basic alice"}).status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer "}).status_code == 401


def test_no_interactive_docs(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


# ---- /me ------------------------------------------------------------------------------------


def test_me_for_a_user(client):
    me = client.get("/me", headers=auth("alice")).json()
    assert me["email"] == ALICE.email and "isAdmin" not in me
    assert me["scansPerDay"] == 5 and me["scansLeftToday"] == 5
    assert me["resetsAt"] == "2026-11-22T00:00:00+00:00"
    assert me["targets"] == [{"id": "lab", "label": "VulnShop lab", "url": LAB, "specUrl": f"{LAB}/openapi.json"}]


# ---- refusals -------------------------------------------------------------------------------


def refusal(client, status, field, **body):
    r = client.post("/scans", json=scan_body(**body), headers=auth("alice"))
    assert r.status_code == status, r.json()
    assert r.json()["field"] == field
    return r.json()["detail"]


def test_consent_is_required(client, runner):
    refusal(client, 400, "authorized", authorized=False)
    assert runner.calls == []


def test_a_host_off_the_allowlist_is_refused(client, runner):
    detail = refusal(client, 403, "target", target="http://example.com", specUrl="http://example.com/openapi.json")
    assert "example.com" in detail and LAB in detail
    # same host, other port; other scheme; a look-alike host
    refusal(client, 403, "target", target="http://127.0.0.1:8001")
    refusal(client, 403, "target", target="https://127.0.0.1:8000")
    refusal(client, 403, "target", target="http://127.0.0.1.example.com:8000")
    assert runner.calls == []


def test_the_spec_must_be_on_the_target(client, runner):
    # The download is a request from this server: it may not go anywhere else (SSRF).
    for spec in ["http://169.254.169.254/latest/meta-data", "http://localhost:8000/openapi.json",
                 "http://127.0.0.1:5432/x", "file:///etc/passwd"]:
        r = client.post("/scans", json=scan_body(specUrl=spec), headers=auth("alice"))
        assert r.status_code in (400, 403) and r.json()["field"] == "specUrl", spec
    assert runner.calls == []


def test_credentials_in_an_address_are_refused(client, runner):
    refusal(client, 400, "target", target="http://u:p@127.0.0.1:8000")
    refusal(client, 400, "specUrl", specUrl="http://u:p@127.0.0.1:8000/openapi.json")
    assert runner.calls == []


def test_malformed_bodies_are_refused_without_echoing_them(client, runner):
    for body in [scan_body(checks=[]), scan_body(checks=["sqlmap"]), scan_body(extra="x"),
                 scan_body(target="x" * 3000), {"target": LAB}]:
        r = client.post("/scans", json=body, headers=auth("alice"))
        assert r.status_code == 400, body
        assert "sqlmap" not in r.text and "xxxx" not in r.text
    assert runner.calls == []


def test_a_huge_body_is_refused(client, runner):
    r = client.post("/scans", content=b"{" + b" " * 20_000 + b"}", headers={**auth("alice"), "Content-Type": "application/json"})
    assert r.status_code == 413
    assert runner.calls == []


def test_a_huge_body_without_a_length_is_refused(client, runner):
    def chunks():
        for _ in range(40):
            yield b" " * 1000

    r = client.post("/scans", content=chunks(), headers={**auth("alice"), "Content-Type": "application/json"})
    assert r.status_code == 413
    assert runner.calls == []


# ---- a scan ---------------------------------------------------------------------------------


def test_a_scan_runs_and_is_stored(client, runner):
    r = client.post("/scans", json=scan_body(checks=["injection", "bola", "bola"]), headers=auth("alice"))
    assert r.status_code == 202
    job = r.json()
    assert job["status"] == "done" and job["target"] == LAB and job["label"] == "VulnShop lab"
    record = client.get(f"/scans/{job['id']}", headers=auth("alice")).json()
    assert record["id"] == job["id"] and record["status"] == "done" and record["report"]["findings"] == []
    # the engine's order, no repeats
    assert runner.calls == [(LAB, f"{LAB}/openapi.json", ["bola", "injection"])]
    assert record["checks"] == ["bola", "injection"] and record["target"] == LAB
    assert record["createdAt"] == "2026-11-21T15:00:00+00:00"
    assert "ownerEmail" not in record
    assert client.get(f"/scans/{record['id']}", headers=auth("alice")).json() == record
    assert [s["id"] for s in client.get("/scans", headers=auth("alice")).json()] == [record["id"]]


def test_a_failed_scan_says_why(client, runner, store):
    runner.fail = ScanFailed("could not log in as test account A", requests_sent=1)
    job = finished(client)
    assert job["status"] == "failed" and "could not log in" in job["error"] and "report" not in job
    assert client.get("/scans", headers=auth("alice")).json() == []  # not in the history...
    assert client.get("/me", headers=auth("alice")).json()["scansLeftToday"] == 4  # ...but it counts


def test_a_scan_that_never_reached_the_target_does_not_count(client, runner):
    runner.fail = ScanFailed("the spec is invalid", requests_sent=0)
    assert finished(client)["status"] == "failed"
    assert client.get("/me", headers=auth("alice")).json()["scansLeftToday"] == 5


# ---- limits ---------------------------------------------------------------------------------


def test_the_daily_limit_per_user(client, runner, clock):
    for _ in range(5):
        assert client.post("/scans", json=scan_body(), headers=auth("alice")).status_code == 202
    r = client.post("/scans", json=scan_body(), headers=auth("alice"))
    assert r.status_code == 429 and r.json()["field"] == "limit" and "midnight UTC" in r.json()["detail"]
    assert len(runner.calls) == 5
    # someone else still can; and the next day alice can again
    assert client.post("/scans", json=scan_body(), headers=auth("bob")).status_code == 202
    clock[0] += timedelta(days=1)
    assert client.post("/scans", json=scan_body(), headers=auth("alice")).status_code == 202


def test_the_daily_limit_for_the_whole_server(make_client):
    client = make_client(global_scans_per_day=2)
    assert client.post("/scans", json=scan_body(), headers=auth("alice")).status_code == 202
    assert client.post("/scans", json=scan_body(), headers=auth("bob")).status_code == 202
    r = client.post("/scans", json=scan_body(), headers=auth("alice"))
    assert r.status_code == 429 and "This server" in r.json()["detail"]


def test_one_scan_at_a_time(make_client, runner):
    client = make_client(start_background=_in_background)  # a real background thread
    runner.block = threading.Event()
    first = start(client)
    assert first.status_code == 202 and first.json()["status"] == "running"
    assert runner.started.wait(5)
    second = start(client, who="bob")
    assert second.status_code == 503 and "Another scan" in second.json()["detail"]
    again = start(client)  # the same user is told it's their own scan
    assert again.status_code == 409 and "still running" in again.json()["detail"]
    runner.block.set()
    assert _wait_for(client, first.json()["id"], "done")
    assert start(client, who="bob").status_code == 202  # the lock was released
    assert len(runner.calls) == 2


def test_requests_per_minute_per_user(make_client):
    client = make_client(requests_per_minute_user=5)
    codes = [client.get("/me", headers=auth("alice")).status_code for _ in range(7)]
    assert codes == [200] * 5 + [429] * 2
    assert client.get("/me", headers=auth("bob")).status_code == 200  # someone else isn't slowed


def test_requests_per_minute_per_address(make_client):
    client = make_client(requests_per_minute_ip=5)
    codes = [client.get("/health").status_code for _ in range(7)]
    assert codes == [200] * 5 + [429] * 2
    r = client.get("/health")
    assert int(r.headers["retry-after"]) >= 1


def test_old_scans_are_deleted(client, clock):
    old = client.post("/scans", json=scan_body(), headers=auth("alice")).json()
    clock[0] += timedelta(days=31)
    client.post("/scans", json=scan_body(), headers=auth("alice"))
    assert client.get(f"/scans/{old['id']}", headers=auth("alice")).status_code == 404


# ---- who sees what --------------------------------------------------------------------------


def test_someone_elses_scan_looks_missing(client):
    mine = client.post("/scans", json=scan_body(), headers=auth("alice")).json()
    r = client.get(f"/scans/{mine['id']}", headers=auth("bob"))
    missing = client.get("/scans/00000000-0000-4000-8000-000000000000", headers=auth("bob"))
    assert r.status_code == missing.status_code == 404
    assert r.json() == missing.json()
    assert client.get("/scans", headers=auth("bob")).json() == []


def test_odd_ids_are_just_missing(client):
    for scan_id in ["1", "..%2Fscans", "%27%20or%201=1", "x" * 100]:
        assert client.get(f"/scans/{scan_id}", headers=auth("alice")).status_code == 404


def test_every_account_sees_only_its_own_scans(client):
    a = client.post("/scans", json=scan_body(), headers=auth("alice")).json()
    b = client.post("/scans", json=scan_body(), headers=auth("bob")).json()
    assert [s["id"] for s in client.get("/scans", headers=auth("alice")).json()] == [a["id"]]
    assert [s["id"] for s in client.get("/scans", headers=auth("bob")).json()] == [b["id"]]
    assert "ownerEmail" not in client.get(f"/scans/{a['id']}", headers=auth("alice")).json()


# ---- the HTTP layer -------------------------------------------------------------------------


def test_security_headers_on_every_answer(client):
    for r in [client.get("/health"), client.get("/me"), client.get("/me", headers=auth("alice"))]:
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in r.headers["content-security-policy"]


def test_cors_only_for_the_web_app(client):
    ok = client.options("/scans", headers={"Origin": "http://127.0.0.1:5173", "Access-Control-Request-Method": "POST",
                                           "Access-Control-Request-Headers": "authorization,content-type"})
    assert ok.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
    assert "access-control-allow-credentials" not in ok.headers
    bad = client.options("/scans", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers
    # a normal answer to the web app carries the header; to another site it doesn't
    assert client.get("/health", headers={"Origin": "http://127.0.0.1:5173"}).headers["access-control-allow-origin"]
    assert "access-control-allow-origin" not in client.get("/health", headers={"Origin": "https://evil.test"}).headers


def test_a_rate_limited_answer_still_reaches_the_web_app(make_client):
    client = make_client(requests_per_minute_ip=5)
    origin = {"Origin": "http://127.0.0.1:5173"}
    for _ in range(5):
        client.get("/health", headers=origin)
    r = client.get("/health", headers=origin)
    assert r.status_code == 429
    assert r.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"  # so the page can show why

