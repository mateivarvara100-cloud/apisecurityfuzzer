"""Tests for the rest of Phase 1: the session manager, the HTML report and headline, and a
ground-truth scan of the real VulnShop lab app (run in-process, no Docker needed)."""

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from apifuzz.cli import app
from apifuzz.errors import SessionError
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Allowlist, Exchange, HttpClient, RecordedRequest, RecordedResponse
from apifuzz.report import headline, to_html
from apifuzz.scanner import ScanResult
from apifuzz.session_manager import authenticate
from apifuzz.settings import Settings

ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


# ---------------------------------------------------------------------------------------------
# session manager


def _client(handler) -> HttpClient:
    return HttpClient(Allowlist(["localhost:8000"]), transport=httpx.MockTransport(handler))


def _settings(**kw) -> Settings:
    return Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], **kw)


class TestSessionManager:
    # Credentials are POSTed to the login path and the token is read from the answer.
    def test_logs_in_both_accounts(self):
        seen = []

        def handler(request):
            body = json.loads(request.content)
            seen.append((request.method, request.url.path, body))
            return httpx.Response(200, json={"access_token": f"tok-{body['username']}"})

        s = authenticate(_client(handler), _settings(user_a="alice", password_a="pa", user_b="bob", password_b="pb"))

        assert (s.token_a, s.token_b) == ("tok-alice", "tok-bob")
        assert seen[0] == ("POST", "/login", {"username": "alice", "password": "pa"})

    # An explicit token wins: no login request is sent for that account.
    def test_explicit_token_wins(self):
        sent = []
        s = authenticate(
            _client(lambda r: sent.append(r) or httpx.Response(200, json={"token": "x"})),
            _settings(token_a="given", user_a="alice", password_a="pa"),
        )
        assert s.token_a == "given" and sent == []

    # No credentials at all: nothing is sent and the settings come back unchanged.
    def test_nothing_to_do(self):
        s = _settings()
        assert authenticate(_client(lambda r: pytest.fail("sent a request")), s) is s

    @pytest.mark.parametrize(
        "response, message",
        [
            (httpx.Response(401, json={"error": "bad"}), "HTTP 401"),
            (httpx.Response(200, json={"hello": "x"}), "no token"),
            (httpx.Response(200, text="not json"), "no token"),
        ],
    )
    def test_login_failures_are_clear_errors(self, response, message):
        with pytest.raises(SessionError, match=message):
            authenticate(_client(lambda r: response), _settings(user_a="alice", password_a="x"))

    # The login path is configurable.
    def test_custom_login_path(self):
        paths = []
        authenticate(
            _client(lambda r: paths.append(r.url.path) or httpx.Response(200, json={"token": "t"})),
            _settings(user_a="a", password_a="b", login_path="/auth/token"),
        )
        assert paths == ["/auth/token"]


# ---------------------------------------------------------------------------------------------
# report


def _finding(severity, endpoint="GET /x", title="t") -> Finding:
    ex = Exchange(
        request=RecordedRequest(method="GET", url="http://x/x", headers={"Authorization": "Bearer secret-a"}),
        response=RecordedResponse(status_code=200, headers={}, body='{"a": "<script>"}'),
        elapsed_ms=3.0,
    )
    return Finding(check="c", severity=severity, title=title, endpoint=endpoint, detail="d", remediation="fix it", evidence=[ex])


class TestReport:
    def test_headline(self):
        result = ScanResult(findings=[_finding(Severity.CRITICAL), _finding(Severity.MEDIUM), _finding(Severity.MEDIUM)], endpoints_scanned=12)
        assert headline(result) == "12 endpoints scanned · 3 findings (1 critical, 2 medium)"
        assert headline(ScanResult(endpoints_scanned=1)) == "1 endpoint scanned · 0 findings"

    # The HTML report is self-contained, escapes everything, and redacts secrets by default.
    def test_html_report(self):
        result = ScanResult(findings=[_finding(Severity.HIGH, title="<b>bad</b>")], checks_run=["c"], endpoints_scanned=1)
        page = to_html(result)

        assert page.startswith("<!doctype html>")
        assert "secret-a" not in page and "[redacted]" in page
        assert "<script>" not in page and "&lt;b&gt;bad&lt;/b&gt;" in page
        assert "fix it" in page
        assert "http://" not in page.split("<main>")[0]  # no external resources in the head
        assert "secret-a" in to_html(result, redact=False)


# ---------------------------------------------------------------------------------------------
# ground truth: scan the real lab app and get exactly its planted flaws


# The lab_api and clean_env fixtures live in conftest.py.


class TestLabGroundTruth:
    def _scan(self, base, *extra):
        return runner.invoke(
            app, ["scan", str(ROOT / "lab" / "openapi.json"), "--i-have-authorization", "--base-url", base, "--json", *extra]
        )

    # Logging in with the lab accounts, the scan finds exactly the planted flaws, and not /me.
    def test_finds_exactly_the_planted_flaws(self, lab_api, clean_env, tmp_path):
        for k, v in {"USER_A": "alice", "PASSWORD_A": "alice", "USER_B": "bob", "PASSWORD_B": "bob"}.items():
            clean_env.setenv(f"APIFUZZ_{k}", v)
        html_file = tmp_path / "report.html"

        result = self._scan(lab_api, "--html", str(html_file))

        assert result.exit_code == 1, result.output
        report = json.loads(result.stdout)
        found = {(f["check"], f["endpoint"], f["severity"]) for f in report["findings"]}
        assert found == {
            ("bola", "GET /orders/{id}", "CRITICAL"),
            ("auth-required", "GET /users/{id}", "HIGH"),
            ("mass-assignment", "PATCH /users/{id}", "CRITICAL"),
            ("rate-limit", "POST /login", "HIGH"),
            ("rate-limit", "GET /search", "MEDIUM"),
            ("injection", "GET /search", "HIGH"),
            ("injection", "POST /login", "HIGH"),
            ("injection", "GET /catalog/{name}", "HIGH"),  # a path parameter
            ("injection", "GET /stock", "HIGH"),  # a header
        }
        assert {f["owasp"].split()[0] for f in report["findings"]} == {
            "API1:2023", "API2:2023", "API3:2023", "API4:2023", "API8:2019",
        }
        # The mass-assignment probe put Alice's role back: the scan leaves the lab as it found it.
        (role,) = [f for f in report["findings"] if f["check"] == "mass-assignment"]
        assert role["key"] == "role" and "put back afterwards" in role["detail"]
        me = httpx.get(f"{lab_api}/me", headers={"Authorization": "Bearer lab-token-alice"}).json()
        assert me["role"] == "user"
        assert report["errors"] == []
        assert "lab-token" not in result.stdout  # tokens from the login are redacted
        page = html_file.read_text(encoding="utf-8")
        assert "GET /orders/{id}" in page and "lab-token" not in page

    # The hardened lab has the flaws fixed: with the same accounts, nothing may be reported.
    def test_hardened_lab_is_clean(self, lab_api, clean_env):
        for k, v in {"USER_A": "alice", "PASSWORD_A": "alice", "USER_B": "bob", "PASSWORD_B": "bob"}.items():
            clean_env.setenv(f"APIFUZZ_{k}", v)
        clean_env.setenv("LAB_HARDENED", "1")

        result = self._scan(lab_api)

        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout)
        assert report["findings"] == [] and report["errors"] == []

    # Without accounts, bola is skipped with a note; the checks that need no login still run.
    def test_without_accounts(self, lab_api, clean_env):
        result = self._scan(lab_api)

        report = json.loads(result.stdout)
        assert [(f["check"], f["endpoint"]) for f in report["findings"]] == [
            ("auth-required", "GET /users/{id}"), ("injection", "POST /login"), ("injection", "GET /search"),
            ("rate-limit", "POST /login"), ("rate-limit", "GET /search"),
        ]
        assert "bola check was skipped" in result.stderr

    # Wrong credentials stop the scan with a clear message instead of a misleading clean report.
    def test_bad_login_stops_the_scan(self, lab_api, clean_env):
        clean_env.setenv("APIFUZZ_USER_A", "alice")
        clean_env.setenv("APIFUZZ_PASSWORD_A", "wrong")

        result = self._scan(lab_api)

        assert result.exit_code == 2
        assert "logging in account A" in result.output and "HTTP 401" in result.output
