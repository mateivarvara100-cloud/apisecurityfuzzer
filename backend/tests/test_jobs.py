"""Scans in the background: progress while they run, Cancel, and who may see or stop them."""

import json
import threading
import time
from pathlib import Path

from apifuzz_web.app import _in_background
from apifuzz_web.config import Config, Target
from apifuzz_web.engine import ScanFailed, ScanOutcome, scan_target
from apifuzz_web.jobs import KEEP_FINISHED_SECONDS, Job, JobBoard
from conftest import ROOT, auth, start, wait_for

CONFIG = Config(supabase_url="https://project.supabase.co")


class SteppingRunner:
    """A fake engine that reports progress like the real one, one step each time it is let go."""

    def __init__(self, steps: int = 3) -> None:
        self.steps = steps
        self.go = threading.Semaphore(0)
        self.at_step = threading.Event()

    def __call__(self, target, spec_url, checks, config, progress) -> ScanOutcome:
        progress.set_phase("spec")
        progress.set_phase("login")
        progress.on_request("POST", f"{target.base_url}/login?api_key=secret", 200)
        for i in range(self.steps):
            if progress.stop_reason():
                return ScanOutcome(report={"findings": [], "coverage": [], "incomplete": True}, requests_sent=i + 1,
                                   stopped_early=True)
            progress.on_step(checks[0], i, self.steps)
            progress.on_request("GET", f"{target.base_url}/orders/{i}", 200)
            self.at_step.set()
            self.go.acquire(timeout=5)
        return ScanOutcome(report={"findings": [], "coverage": []}, requests_sent=self.steps + 1)


def test_progress_while_running_then_done(make_client):
    stepping = SteppingRunner()
    client = make_client(start_background=_in_background, use_runner=stepping)

    job = start(client).json()
    assert job["status"] == "running" and job["progress"]["maxRequests"] == 400
    assert stepping.at_step.wait(5)
    view = client.get(f"/scans/{job['id']}/progress", headers=auth("alice")).json()
    assert view["status"] == "running"
    assert view["progress"]["phase"] == "checks" and view["progress"]["check"] == "bola"
    assert view["progress"]["step"] == 1 and view["progress"]["steps"] == 3
    assert view["progress"]["requestsSent"] == 2
    # The feed shows paths only: a query string could carry an API key.
    assert view["progress"]["recent"][0] == {"method": "POST", "path": "/login", "status": 200}
    assert "secret" not in json.dumps(view)
    # GET /scans/{id} says the same while it runs, and the account sees it in /me.
    assert client.get(f"/scans/{job['id']}", headers=auth("alice")).json()["status"] == "running"
    assert client.get("/me", headers=auth("alice")).json()["runningScan"] == {"id": job["id"], "label": "VulnShop lab"}
    for _ in range(3):
        stepping.go.release()
    assert wait_for(client, job["id"], "done")
    record = client.get(f"/scans/{job['id']}", headers=auth("alice")).json()
    assert record["status"] == "done" and "report" in record
    assert client.get("/me", headers=auth("alice")).json()["runningScan"] is None


def test_cancel_stops_between_steps_and_keeps_the_partial_report(make_client):
    stepping = SteppingRunner(steps=10)
    client = make_client(start_background=_in_background, use_runner=stepping)

    job = start(client).json()
    assert stepping.at_step.wait(5)
    r = client.post(f"/scans/{job['id']}/cancel", headers=auth("alice"))
    assert r.status_code == 202 and r.json()["cancelRequested"] is True
    stepping.go.release()
    done = wait_for(client, job["id"], "done")
    assert done and done["stoppedEarly"] is True
    record = client.get(f"/scans/{job['id']}", headers=auth("alice")).json()
    assert record["report"]["incomplete"] is True
    # It reached the target, so it counts towards the day's scans.
    assert client.get("/me", headers=auth("alice")).json()["scansLeftToday"] == 4


def test_cancelled_before_the_checks_started(make_client, store):
    gate = threading.Event()

    def before_checks(target, spec_url, checks, config, progress):
        gate.wait(5)
        if progress.stop_reason():
            raise ScanFailed("the scan was cancelled before the checks started.", requests_sent=0)
        return ScanOutcome(report={}, requests_sent=1)

    client = make_client(start_background=_in_background, use_runner=before_checks)
    job = start(client).json()
    client.post(f"/scans/{job['id']}/cancel", headers=auth("alice"))
    gate.set()
    view = wait_for(client, job["id"], "cancelled")
    assert view and "cancelled before the checks started" in view["error"]
    assert store._rows == []  # nothing reached the target: not stored, not counted
    assert start(client).status_code == 202  # and the lock was released


def test_someone_elses_running_scan_looks_missing(make_client, runner):
    runner.block = threading.Event()
    client = make_client(start_background=_in_background)
    job = start(client).json()
    assert runner.started.wait(5)
    try:
        for path in (f"/scans/{job['id']}", f"/scans/{job['id']}/progress"):
            assert client.get(path, headers=auth("bob")).status_code == 404
        assert client.post(f"/scans/{job['id']}/cancel", headers=auth("bob")).status_code == 404
        # ...and it is still running: bob's cancel did nothing.
        assert client.get(f"/scans/{job['id']}/progress", headers=auth("alice")).json()["cancelRequested"] is False
    finally:
        runner.block.set()
    assert wait_for(client, job["id"], "done")


def test_odd_ids_on_the_new_routes_are_just_missing(client):
    for scan_id in ["1", "%27%20or%201=1", "x" * 100, "00000000-0000-4000-8000-000000000000"]:
        assert client.get(f"/scans/{scan_id}/progress", headers=auth("alice")).status_code == 404
        assert client.post(f"/scans/{scan_id}/cancel", headers=auth("alice")).status_code == 404


def test_the_new_routes_need_a_sign_in(client):
    some = "00000000-0000-4000-8000-000000000000"
    assert client.get(f"/scans/{some}/progress").status_code == 401
    assert client.post(f"/scans/{some}/cancel").status_code == 401


def test_watching_a_scan_has_its_own_allowance(make_client):
    client = make_client(requests_per_minute_user=5, requests_per_minute_ip=500)
    job = start(client).json()
    codes = [client.get(f"/scans/{job['id']}/progress", headers=auth("alice")).status_code for _ in range(20)]
    assert codes == [200] * 20
    # ...and polling didn't use up the general allowance (one was spent starting the scan).
    assert [client.get("/me", headers=auth("alice")).status_code for _ in range(4)] == [200] * 4


def test_a_crash_inside_the_scan_fails_it_and_frees_the_server(make_client):
    def crash(*_):
        raise RuntimeError("boom")

    client = make_client(use_runner=crash)
    job = start(client).json()
    assert job["status"] == "failed" and "unexpected error" in job["error"] and "boom" not in job["error"]
    assert start(client).status_code == 202  # the lock was released


def test_finished_jobs_are_forgotten_after_a_while():
    board = JobBoard(clock=lambda: now[0])
    now = [1000.0]
    job = Job(id="j", user_id="u", label="l", target="t", checks=[], created_at="", max_requests=1)
    board.add(job)
    job.finish("done")
    job.finished_at = now[0]
    assert board.get("j") is job
    now[0] += KEEP_FINISHED_SECONDS + 1
    assert board.get("j") is None


# ---- the real engine, reporting to a real job ------------------------------------------------------


def _lab(url: str) -> Target:
    env = {"APIFUZZ_USER_A": "alice", "APIFUZZ_PASSWORD_A": "alice", "APIFUZZ_USER_B": "bob", "APIFUZZ_PASSWORD_B": "bob"}
    return Target(id="lab", label="lab", base_url=url, spec_url=f"{url}/openapi.json", engine_env=env)


def _job() -> Job:
    return Job(id="j", user_id="u", label="lab", target="", checks=[], created_at="", max_requests=400)


def test_a_real_scan_reports_its_progress(lab_url):
    job = _job()
    outcome = scan_target(_lab(lab_url), f"{lab_url}/openapi.json", ["auth-required", "bola"], CONFIG, job)
    view = job.view()["progress"]
    assert view["phase"] == "saving"
    assert view["requestsSent"] == outcome.requests_sent > 0
    assert view["steps"] == view["step"] == 2 * outcome.report["endpoints_scanned"]
    assert all("?" not in r["path"] for r in view["recent"])
    assert outcome.stopped_early is False


def test_a_real_scan_cancelled_midway_keeps_what_it_found(lab_url):
    job = _job()
    original = job.on_step

    def cancel_halfway(check, index, total):
        original(check, index, total)
        if index == total // 2:
            job.request_cancel()

    job.on_step = cancel_halfway  # type: ignore[method-assign]
    outcome = scan_target(_lab(lab_url), f"{lab_url}/openapi.json", ["auth-required"], CONFIG, job)
    assert outcome.stopped_early is True
    assert outcome.report["incomplete"] is True
    assert "scan stopped early: cancelled by the user" in outcome.report["errors"]
    assert job.view()["progress"]["step"] < job.view()["progress"]["steps"]


def test_a_real_scan_can_be_cancelled_while_the_target_wakes():
    job = _job()
    job.request_cancel()
    target = Target(id="lab", label="lab", base_url="http://127.0.0.1:9", spec_url="http://127.0.0.1:9/openapi.json",
                    health_url="http://127.0.0.1:9/health")
    started = time.monotonic()
    try:
        scan_target(target, target.spec_url, ["bola"], CONFIG, job)
    except ScanFailed as exc:
        assert "cancelled before it started" in str(exc) and exc.requests_sent == 0
    else:
        raise AssertionError("expected the scan to stop")
    assert time.monotonic() - started < 2  # not the whole wake timeout


def test_a_real_scan_of_an_uploaded_spec_downloads_nothing(lab_url):
    text = (Path(ROOT) / "lab" / "openapi.json").read_text(encoding="utf-8")
    target = Target(id="t", label="lab", base_url=lab_url, spec_url="", spec_text=text, spec_name="openapi.json",
                    engine_env=_lab(lab_url).engine_env)
    outcome = scan_target(target, "", ["bola"], CONFIG, None)
    assert any(f["check"] == "bola" and f["endpoint"] == "GET /orders/{id}" for f in outcome.report["findings"])
