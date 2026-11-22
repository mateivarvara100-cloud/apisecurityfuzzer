"""Real scans through the real engine, against the VulnShop lab running in this process."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from apifuzz_web.config import Config, Target
from apifuzz_web.engine import ScanFailed, scan_target, wake


def lab_target(url: str, **accounts: str) -> Target:
    env = {"APIFUZZ_USER_A": "alice", "APIFUZZ_PASSWORD_A": "alice", "APIFUZZ_USER_B": "bob", "APIFUZZ_PASSWORD_B": "bob"}
    env.update(accounts)
    return Target(id="lab", label="lab", base_url=url, spec_url=f"{url}/openapi.json", engine_env=env)


CONFIG = Config(supabase_url="https://project.supabase.co")


def test_a_lab_scan_finds_the_planted_bola(lab_url):
    outcome = scan_target(lab_target(lab_url), f"{lab_url}/openapi.json", ["bola"], CONFIG)
    findings = outcome.report["findings"]
    assert any(f["check"] == "bola" and f["endpoint"] == "GET /orders/{id}" for f in findings), findings
    assert outcome.report["checks_run"] == ["bola"]
    assert outcome.requests_sent > 0


def test_the_report_never_carries_the_test_accounts_tokens(lab_url):
    outcome = scan_target(lab_target(lab_url), f"{lab_url}/openapi.json", ["bola", "auth-required"], CONFIG)
    text = str(outcome.report)
    assert "Authorization" in text  # the evidence does show the headers that were sent...
    assert "lab-token-alice" not in text and "lab-token-bob" not in text  # ...but never the tokens in them


def test_the_servers_environment_never_reaches_the_engine(lab_url, monkeypatch):
    # The engine would normally read APIFUZZ_* from the environment. Here it must not: a server
    # setting could otherwise send another account's password, or widen the allowlist.
    monkeypatch.setenv("APIFUZZ_ALLOWLIST", "evil.test")
    monkeypatch.setenv("APIFUZZ_TOKEN_A", "server-secret")
    outcome = scan_target(lab_target(lab_url), f"{lab_url}/openapi.json", ["auth-required"], CONFIG)
    assert "server-secret" not in str(outcome.report)


def test_a_wrong_password_stops_the_scan(lab_url):
    with pytest.raises(ScanFailed) as caught:
        scan_target(lab_target(lab_url, APIFUZZ_PASSWORD_A="wrong"), f"{lab_url}/openapi.json", ["bola"], CONFIG)
    assert caught.value.requests_sent >= 1


class Redirector(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.end_headers()

    def log_message(self, *args):
        pass


def test_a_redirected_spec_is_not_followed():
    # A target whose spec URL redirects to the cloud metadata address: the classic SSRF.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(ScanFailed) as caught:
            scan_target(lab_target(url), f"{url}/openapi.json", ["bola"], CONFIG)
        assert "redirect" in str(caught.value).lower()
    finally:
        server.shutdown()
        server.server_close()


def test_nothing_answering_is_a_failure_not_a_clean_report():
    with pytest.raises(ScanFailed):
        # nothing listens on port 9 (discard) on a test machine
        scan_target(lab_target("http://127.0.0.1:9"), "http://127.0.0.1:9/openapi.json", ["bola"], CONFIG)


class FakeTime:
    """A clock that only moves when the code under test sleeps, so waiting tests run instantly."""

    def __init__(self) -> None:
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def answers(*replies: httpx.Response | Exception):
    """A transport that gives these replies in order (repeating the last), recording each URL."""
    seen: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        reply = replies[min(len(seen), len(replies)) - 1]
        if isinstance(reply, Exception):
            raise reply
        return reply

    return httpx.MockTransport(handle), seen


JSON_OK = httpx.Response(200, json={"status": "ok"})
STARTING_PAGE = httpx.Response(200, text="<html>Service waking up</html>", headers={"content-type": "text/html"})


def test_wake_waits_through_refusals_and_a_starting_page():
    transport, seen = answers(httpx.ConnectError("refused"), httpx.Response(503), STARTING_PAGE, JSON_OK)
    t = FakeTime()
    wake("http://127.0.0.1:8000/health", 30, transport=transport, sleep=t.sleep, clock=t.clock)
    assert len(seen) == 4 and set(seen) == {"http://127.0.0.1:8000/health"}
    assert t.now < 30


def test_wake_gives_up_in_time_having_sent_nothing_to_the_api():
    transport, seen = answers(httpx.ConnectError("refused"))
    t = FakeTime()
    with pytest.raises(ScanFailed) as caught:
        wake("http://127.0.0.1:8000/health", 30, transport=transport, sleep=t.sleep, clock=t.clock)
    assert caught.value.requests_sent == 0  # so it doesn't count towards the user's daily scans
    assert "30 seconds" in str(caught.value)
    assert 30 <= t.now < 33 and set(seen) == {"http://127.0.0.1:8000/health"}


def test_wake_never_follows_a_redirect():
    transport, seen = answers(httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))
    t = FakeTime()
    with pytest.raises(ScanFailed):
        wake("http://127.0.0.1:8000/health", 10, transport=transport, sleep=t.sleep, clock=t.clock)
    assert set(seen) == {"http://127.0.0.1:8000/health"}


def test_wake_is_skipped_when_switched_off():
    transport, seen = answers(httpx.ConnectError("refused"))
    wake("http://127.0.0.1:8000/health", 0, transport=transport)
    assert seen == []


def test_a_scan_wakes_the_lab_first(lab_url):
    target = Target(**{**lab_target(lab_url).__dict__, "health_url": f"{lab_url}/health"})
    outcome = scan_target(target, f"{lab_url}/openapi.json", ["bola"], CONFIG)
    assert any(f["check"] == "bola" for f in outcome.report["findings"])


def test_a_lab_that_never_comes_up_fails_before_any_scan_request():
    target = Target(**{**lab_target("http://127.0.0.1:9").__dict__, "health_url": "http://127.0.0.1:9/health"})
    with pytest.raises(ScanFailed) as caught:
        scan_target(target, "http://127.0.0.1:9/openapi.json", ["bola"], Config(supabase_url="https://p.supabase.co", wake_timeout=1))
    assert caught.value.requests_sent == 0 and "1 seconds" in str(caught.value)


def test_a_users_api_on_an_internal_address_is_refused_before_anything_is_sent(lab_url):
    # The lab is on 127.0.0.1. As a user's own API (guarded), it must not be reachable at all.
    target = Target(**{**lab_target(lab_url).__dict__, "guarded": True})
    with pytest.raises(ScanFailed) as caught:
        scan_target(target, f"{lab_url}/openapi.json", ["bola"], CONFIG)
    assert caught.value.requests_sent == 0
    assert "not a public internet address" in str(caught.value)


def test_a_users_api_is_not_scanned_through_a_proxy(lab_url, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    target = Target(**{**lab_target(lab_url).__dict__, "guarded": True})
    with pytest.raises(ScanFailed, match="proxy"):
        scan_target(target, f"{lab_url}/openapi.json", ["bola"], CONFIG)
