"""Users' own APIs: adding one, approval by hand, who sees what, and scanning it with two test tokens.

The self-service proof and spec uploads are in test_proof_upload.py.
"""

import json
import logging
import socket
from dataclasses import asdict

import pytest

from apifuzz_web import app as app_module
from apifuzz_web import netguard
from apifuzz_web.config import Config, Target
from apifuzz_web.engine import Progress, ScanOutcome
from conftest import ALICE, auth

API = "https://api.example.com"
SPEC = f"{API}/openapi.json"
TOKEN_A, TOKEN_B = "secret-token-of-account-a-1234", "secret-token-of-account-b-5678"


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    """Names resolve from this table instead of the internet; unknown names don't resolve."""
    table = {"api.example.com": ["93.184.216.34"], "other.example.com": ["93.184.216.35"],
             "intranet.example.com": ["10.0.0.5"], "sneaky.example.com": ["93.184.216.36", "169.254.169.254"]}

    def resolve(host, port, **_):
        if host not in table:
            raise socket.gaierror("no such name")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in table[host]]

    monkeypatch.setattr(app_module, "public_addresses",
                        lambda host, port: netguard.public_addresses(host, port, resolve))
    return table


class RecordingRunner:
    """Stands in for the engine and keeps the Target it was given, tokens included."""

    def __init__(self) -> None:
        self.targets: list[Target] = []

    def __call__(self, target: Target, spec_url: str, checks: list[str], config: Config,
                 progress: Progress) -> ScanOutcome:
        self.targets.append(target)
        return ScanOutcome(report={"findings": [], "coverage": [], "checks_run": checks}, requests_sent=20)


@pytest.fixture
def runner():
    return RecordingRunner()


def add(client, who="alice", **overrides):
    body = {"label": "Orders API", "url": API, "specUrl": SPEC, "authorized": True}
    body.update(overrides)
    return client.post("/targets", json=body, headers=auth(who))


def approve(store, url=API, status="approved", note=None):
    for t in store._targets:  # what the operator does by hand in the Supabase table editor
        if t.base_url == url:
            store.set_status(t.id, status, note)


def scan(client, who="alice", **overrides):
    body = {"target": API, "specUrl": SPEC, "checks": ["bola", "auth-required"], "authorized": True,
            "tokenA": TOKEN_A, "tokenB": TOKEN_B}
    body.update(overrides)
    return client.post("/scans", json=body, headers=auth(who))


# ---- adding an API ---------------------------------------------------------------------------------


def test_target_routes_need_a_sign_in(client):
    assert client.get("/targets").status_code == 401
    assert client.post("/targets", json={}).status_code == 401
    assert client.delete(f"/targets/{ALICE.id}").status_code == 401


def test_an_added_api_waits_for_approval(client):
    r = add(client, label="  Orders   API ", url="https://API.example.com/v1/")
    assert r.status_code == 201
    t = r.json()
    assert t["label"] == "Orders API" and t["url"] == API and t["status"] == "pending"
    assert "scansLeftToday" not in t  # only an approved API can be scanned
    listed = client.get("/targets", headers=auth("alice")).json()
    assert [x["id"] for x in listed["targets"]] == [t["id"]]
    assert listed["maxTargets"] == 3 and listed["scansPerTargetPerDay"] == 3


@pytest.mark.parametrize("overrides, status, field, says", [
    ({"authorized": False}, 400, "authorized", "own this API"),
    ({"url": "http://api.example.com", "specUrl": "http://api.example.com/openapi.json"}, 400, "url", "https"),
    ({"url": "https://api.example.com:8080"}, 400, "url", "443 or 8443"),
    ({"specUrl": "https://other.example.com/openapi.json"}, 400, "specUrl", "API's own address"),
    ({"url": "https://intranet.example.com", "specUrl": "https://intranet.example.com/s.json"}, 400, "url",
     "not a public internet address"),
    ({"url": "https://sneaky.example.com", "specUrl": "https://sneaky.example.com/s.json"}, 400, "url",
     "169.254.169.254"),
    ({"url": "https://nowhere.example.com", "specUrl": "https://nowhere.example.com/s.json"}, 400, "url",
     "doesn't resolve"),
    ({"label": "   "}, 400, "label", "1 to 60"),
    ({"label": "x" * 61}, 400, "label", "1 to 60"),
])
def test_an_api_that_cant_be_added_says_why(client, overrides, status, field, says):
    r = add(client, **overrides)
    assert r.status_code == status, r.json()
    assert r.json()["field"] == field and says in r.json()["detail"]
    assert client.get("/targets", headers=auth("alice")).json()["targets"] == []


def test_the_same_api_twice_is_refused(client):
    assert add(client).status_code == 201
    r = add(client, url=f"{API}/", label="Again")
    assert r.status_code == 409 and r.json()["field"] == "url"


def test_at_most_three_apis_per_account(client, dns):
    for i in range(3):
        dns[f"api{i}.example.com"] = ["93.184.216.40"]
        assert add(client, url=f"https://api{i}.example.com", specUrl=f"https://api{i}.example.com/s.json").status_code == 201
    r = add(client)
    assert r.status_code == 429 and r.json()["field"] == "limit"


# ---- who sees and removes what ---------------------------------------------------------------------


def test_others_never_see_or_remove_your_apis(client):
    mine = add(client).json()
    assert client.get("/targets", headers=auth("bob")).json()["targets"] == []
    assert client.delete(f"/targets/{mine['id']}", headers=auth("bob")).status_code == 404
    assert len(client.get("/targets", headers=auth("alice")).json()["targets"]) == 1


def test_removing_your_own_api(client):
    mine = add(client).json()
    assert client.delete(f"/targets/{mine['id']}", headers=auth("alice")).status_code == 204
    assert client.get("/targets", headers=auth("alice")).json()["targets"] == []
    assert client.delete(f"/targets/{mine['id']}", headers=auth("alice")).status_code == 404
    assert client.delete("/targets/not-a-uuid", headers=auth("alice")).status_code == 404


# ---- scanning it -------------------------------------------------------------------------------------


def test_a_pending_or_rejected_api_cant_be_scanned(client, store, runner):
    add(client)
    r = scan(client)
    assert r.status_code == 403 and "isn't approved yet" in r.json()["detail"]
    approve(store, status="rejected", note="Not your domain")
    r = scan(client)
    assert r.status_code == 403 and "wasn't approved" in r.json()["detail"]
    assert runner.targets == []


def test_someone_elses_approved_api_cant_be_scanned(client, store, runner):
    add(client)
    approve(store)
    r = scan(client, who="bob")
    assert r.status_code == 403 and r.json()["field"] == "target"
    assert runner.targets == []


def test_an_approved_api_is_scanned_guarded_with_the_two_tokens(client, store, runner):
    add(client)
    approve(store)
    r = scan(client, tokenA=f"Bearer {TOKEN_A}")
    assert r.status_code == 202, r.json()
    (target,) = runner.targets
    assert target.guarded is True and target.base_url == API and target.spec_url == SPEC
    assert target.engine_env == {"APIFUZZ_TOKEN_A": TOKEN_A, "APIFUZZ_TOKEN_B": TOKEN_B}
    assert target.health_url == ""
    assert target.spec_text is None  # linked, not uploaded


def test_an_api_approved_by_hand_needs_no_proof_file(client, store, proof):
    add(client)
    approve(store)
    assert scan(client).status_code == 202
    assert proof.checked == []


def test_the_tokens_are_never_stored_returned_or_logged(client, store, caplog):
    add(client)
    approve(store)
    with caplog.at_level(logging.DEBUG):
        r = scan(client)
    assert r.status_code == 202
    stored = json.dumps([asdict(row) for row in store._rows]) + json.dumps([asdict(t) for t in store._targets])
    for token in (TOKEN_A, TOKEN_B):
        assert token not in stored
        assert token not in r.text
        assert token not in caplog.text


def test_a_scan_without_tokens_runs_without_accounts(client, store, runner):
    add(client)
    approve(store)
    assert scan(client, tokenA=None, tokenB="  ").status_code == 202
    assert runner.targets[0].engine_env == {}


@pytest.mark.parametrize("overrides, field, says", [
    ({"tokenB": TOKEN_A}, "tokenB", "different tokens"),
    ({"tokenA": "abc def"}, "tokenA", "can't carry"),
    ({"tokenA": "abc\r\nX-Injected: 1"}, "tokenA", "can't carry"),
    ({"specUrl": f"{API}/other-spec.json"}, "specUrl", "different spec"),
])
def test_bad_tokens_or_another_spec_are_refused(client, store, runner, overrides, field, says):
    add(client)
    approve(store)
    r = scan(client, **overrides)
    assert r.status_code in (400, 403) and r.json()["field"] == field and says in r.json()["detail"]
    assert runner.targets == []


def test_a_too_long_token_is_refused_without_echoing_it(client, store):
    add(client)
    approve(store)
    r = scan(client, tokenA="t" * 5000)
    assert r.status_code == 400 and "tttt" not in r.text


def test_an_api_is_scanned_at_most_three_times_a_day_whoever_asks(client, store):
    add(client)
    add(client, who="bob")  # the same API, added by a second account
    approve(store)
    for _ in range(3):
        assert scan(client).status_code == 202
    listed = client.get("/targets", headers=auth("alice")).json()["targets"]
    assert listed[0]["scansLeftToday"] == 0
    r = scan(client, who="bob")
    assert r.status_code == 429 and r.json()["field"] == "limit" and "3 times" in r.json()["detail"]


def test_scans_of_your_api_count_towards_your_daily_scans(client, store):
    add(client)
    approve(store)
    scan(client)
    assert client.get("/me", headers=auth("alice")).json()["scansLeftToday"] == 4


def test_the_lab_still_ignores_tokens(client, runner):
    from conftest import LAB
    r = client.post("/scans", headers=auth("alice"), json={
        "target": LAB, "specUrl": f"{LAB}/openapi.json", "checks": ["bola"], "authorized": True, "tokenA": TOKEN_A})
    assert r.status_code == 202
    assert runner.targets[0].guarded is False and "APIFUZZ_TOKEN_A" not in runner.targets[0].engine_env

