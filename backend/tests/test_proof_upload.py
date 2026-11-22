"""Self-service proof of control (a file on the API), and specs uploaded instead of linked."""

import json
from pathlib import Path

import httpx
import pytest

from apifuzz_web.proof import ProofMissing, check_proof, proof_line
from conftest import ROOT, auth
from test_targets import API, SPEC, RecordingRunner, add, approve, dns, scan  # noqa: F401 (dns is a fixture)

LAB_SPEC = (Path(ROOT) / "lab" / "openapi.json").read_text(encoding="utf-8")


@pytest.fixture
def runner():
    return RecordingRunner()


def publish(proof, target: dict) -> None:
    """Put the API's proof line where the (fake) fetch finds it."""
    line = target["proof"]["line"]
    proof.published.add((target["url"], line.removeprefix("apifuzz-verify=")))


# ---- the proof file itself -----------------------------------------------------------------------


def _serve(handler):
    return httpx.MockTransport(handler)


def test_the_proof_is_found_among_other_lines():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, text=f"# for other tools\n{proof_line('other')}\n  {proof_line('abc')}  \n")

    check_proof(API, "abc", _serve(handler))
    (request,) = seen
    assert str(request.url) == f"{API}/.well-known/apifuzz-verify.txt" and request.method == "GET"
    assert "authorization" not in request.headers and "cookie" not in request.headers


@pytest.mark.parametrize("response, says", [
    (httpx.Response(404), "HTTP 404"),
    (httpx.Response(302, headers={"Location": "https://elsewhere.example.com/x"}), "redirects"),
    (httpx.Response(200, text="apifuzz-verify=someone-else"), "doesn't contain"),
    (httpx.Response(200, text="apifuzz-verify=abcdef"), "doesn't contain"),  # a prefix isn't the token
    (httpx.Response(200, text="x" * 70_000), "larger than 64 KB"),
])
def test_anything_else_is_no_proof(response, says):
    with pytest.raises(ProofMissing, match=says):
        check_proof(API, "abc", _serve(lambda r: response))


def test_an_unreachable_api_is_no_proof():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(ProofMissing, match="couldn't fetch"):
        check_proof(API, "abc", _serve(handler))


def test_the_real_fetch_refuses_an_internal_address():
    # Without a test transport the fetch goes through the public-address guard.
    for base in ("https://10.0.0.5", "https://169.254.169.254", "https://127.0.0.1:8443"):
        with pytest.raises(ProofMissing, match="not a public internet address"):
            check_proof(base, "abc")


def test_the_real_fetch_refuses_when_a_proxy_is_set(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    with pytest.raises(ProofMissing, match="proxy"):
        check_proof(API, "abc")


# ---- proving control through the API -------------------------------------------------------------


def test_an_added_api_comes_with_its_proof(client):
    t = add(client).json()
    assert t["status"] == "pending" and t["verifiedAt"] is None
    assert t["proof"]["url"] == f"{API}/.well-known/apifuzz-verify.txt"
    token = t["proof"]["line"].removeprefix("apifuzz-verify=")
    assert len(token) == 32 and int(token, 16) >= 0
    # Every account gets its own token, even for the same API.
    other = add(client, who="bob").json()
    assert other["proof"]["line"] != t["proof"]["line"]


def test_verifying_approves_it_and_it_can_be_scanned(client, proof, runner):
    t = add(client).json()
    r = client.post(f"/targets/{t['id']}/verify", headers=auth("alice"))
    assert r.status_code == 422 and "HTTP 404" in r.json()["detail"]
    assert client.get("/targets", headers=auth("alice")).json()["targets"][0]["status"] == "pending"

    publish(proof, t)
    r = client.post(f"/targets/{t['id']}/verify", headers=auth("alice"))
    assert r.status_code == 200 and r.json()["status"] == "approved" and r.json()["verifiedAt"]
    assert r.json()["scansLeftToday"] == 3 and "proof" in r.json()  # still shown: keep the file there
    assert scan(client).status_code == 202 and len(runner.targets) == 1


def test_taking_the_file_down_withdraws_permission(client, proof, runner):
    t = add(client).json()
    publish(proof, t)
    client.post(f"/targets/{t['id']}/verify", headers=auth("alice"))
    proof.published.clear()
    r = scan(client)
    assert r.status_code == 403 and r.json()["field"] == "target" and "is gone" in r.json()["detail"]
    assert runner.targets == []


def test_a_rejected_api_stays_rejected(client, store, proof):
    t = add(client).json()
    approve(store, status="rejected", note="Not your domain")
    publish(proof, t)
    r = client.post(f"/targets/{t['id']}/verify", headers=auth("alice"))
    assert r.status_code == 403 and "admin" in r.json()["detail"]
    listed = client.get("/targets", headers=auth("alice")).json()["targets"][0]
    assert listed["status"] == "rejected" and "proof" not in listed


def test_someone_elses_proof_is_no_proof(client, proof):
    alice = add(client).json()
    bob = add(client, who="bob").json()
    publish(proof, alice)  # alice controls the API; bob only added it
    assert client.post(f"/targets/{bob['id']}/verify", headers=auth("bob")).status_code == 422
    assert client.post(f"/targets/{alice['id']}/verify", headers=auth("bob")).status_code == 404


def test_checks_are_rate_limited(client):
    t = add(client).json()
    codes = [client.post(f"/targets/{t['id']}/verify", headers=auth("alice")).status_code for _ in range(12)]
    assert codes == [422] * 10 + [429] * 2


def test_verifying_an_approved_api_fetches_nothing(client, store, proof):
    t = add(client).json()
    approve(store)
    assert client.post(f"/targets/{t['id']}/verify", headers=auth("alice")).json()["status"] == "approved"
    assert proof.checked == []


def test_verify_needs_a_sign_in_and_a_real_id(client):
    assert client.post("/targets/00000000-0000-4000-8000-000000000000/verify").status_code == 401
    assert client.post("/targets/nope/verify", headers=auth("alice")).status_code == 404


# ---- uploading a spec ----------------------------------------------------------------------------


def upload(name="openapi.json", text=LAB_SPEC) -> dict:
    return {"spec": {"name": name, "text": text}}


def test_an_api_can_be_added_with_an_uploaded_spec(client, store):
    r = client.post("/targets", headers=auth("alice"), json={
        "label": "Orders API", "url": API, "authorized": True, **upload("C:\\work\\specs\\orders.json")})
    assert r.status_code == 201, r.json()
    t = r.json()
    assert t["specUrl"] is None and t["specName"] == "orders.json"  # folders dropped
    assert "spec_text" not in r.text and "VulnShop" not in r.text  # the text isn't sent back
    listed = client.get("/targets", headers=auth("alice")).json()["targets"][0]
    assert listed["specName"] == "orders.json"
    assert store.get_spec_text(t["id"], "11111111-1111-4111-8111-111111111111") == LAB_SPEC


def test_an_uploaded_spec_is_what_gets_scanned(client, store, runner):
    client.post("/targets", headers=auth("alice"), json={"label": "Orders", "url": API, "authorized": True, **upload()})
    approve(store)
    r = scan(client, specUrl="")
    assert r.status_code == 202, r.json()
    (target,) = runner.targets
    assert target.spec_text == LAB_SPEC and target.spec_name == "openapi.json" and target.spec_url == ""
    assert store._rows[0].spec_url == "uploaded: openapi.json"


BOMB = "\n".join(["openapi: 3.0.3", "info: {title: t, version: '1'}", "paths: {}", "x-a0: &a0 [x, x, x, x, x]"]
                 + [f"x-a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]" for i in range(1, 9)])


@pytest.mark.parametrize("body, says", [
    (upload(text="not: [a spec"), "openapi.json"),
    (upload(text=json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}})),
     "no endpoints"),
    (upload(text=BOMB, name="bomb.yaml"), "YAML aliases"),
    (upload(text=json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {
        "/a": {"get": {"responses": {"200": {"$ref": "http://169.254.169.254/x#/r"}}}}}})), "outside the spec"),
    ({"spec": {"name": "big.json", "text": "x" * 1_000_001}}, "malformed"),
    ({"spec": {"name": "big.json", "text": "é" * 600_000}}, "larger than 1 MB"),
    ({"specUrl": SPEC, **upload()}, "one of the two"),
    ({}, "one of the two"),
])
def test_an_unusable_upload_says_why(client, body, says):
    r = client.post("/targets", headers=auth("alice"), json={"label": "Orders", "url": API, "authorized": True, **body})
    assert r.status_code == 400, r.json()
    assert says in r.json()["detail"]
    assert client.get("/targets", headers=auth("alice")).json()["targets"] == []


def test_the_spec_can_be_replaced_by_a_link_or_a_new_upload(client, store, runner):
    t = add(client).json()
    approve(store)
    r = client.put(f"/targets/{t['id']}/spec", headers=auth("alice"), json=upload("v2.yaml"))
    assert r.status_code == 200 and r.json()["specName"] == "v2.yaml" and r.json()["specUrl"] is None
    assert r.json()["status"] == "approved"  # control of the API is what was proven, not the spec
    r = client.put(f"/targets/{t['id']}/spec", headers=auth("alice"), json={"specUrl": f"{API}/v3.json"})
    assert r.json()["specUrl"] == f"{API}/v3.json" and r.json()["specName"] is None
    assert store.get_spec_text(t["id"], "11111111-1111-4111-8111-111111111111") is None
    r = client.put(f"/targets/{t['id']}/spec", headers=auth("alice"), json={"specUrl": "https://other.example.com/s"})
    assert r.status_code == 400 and r.json()["field"] == "specUrl"


def test_only_the_owner_can_replace_a_spec(client):
    t = add(client).json()
    assert client.put(f"/targets/{t['id']}/spec", headers=auth("bob"), json=upload()).status_code == 404
    assert client.put("/targets/nope/spec", headers=auth("alice"), json=upload()).status_code == 404
    assert client.put(f"/targets/{t['id']}/spec", json=upload()).status_code == 401


def test_uploads_are_rate_limited(make_client):
    client = make_client(requests_per_minute_user=100, requests_per_minute_ip=500)
    t = add(client).json()
    codes = [client.put(f"/targets/{t['id']}/spec", headers=auth("alice"), json=upload()).status_code for _ in range(8)]
    assert codes == [200] * 6 + [429] * 2


def test_only_upload_routes_take_a_large_body(client):
    big = {"label": "Orders", "url": API, "authorized": True, **upload(text=LAB_SPEC + " " * 200_000)}
    assert client.post("/targets", headers=auth("alice"), json=big).status_code == 201
    padded = json.dumps({"target": API, "checks": ["bola"], "authorized": True, "specUrl": " " * 200_000})
    r = client.post("/scans", content=padded, headers={**auth("alice"), "Content-Type": "application/json"})
    assert r.status_code == 413
    huge = json.dumps(upload(text="x" * 1_600_000))
    r = client.post("/targets", content=huge, headers={**auth("alice"), "Content-Type": "application/json"})
    assert r.status_code == 413
