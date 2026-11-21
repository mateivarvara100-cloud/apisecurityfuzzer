"""Real scans through the real engine, against the VulnShop lab running in this process."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from apifuzz_web.config import Config, Target
from apifuzz_web.engine import ScanFailed, scan_target


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
