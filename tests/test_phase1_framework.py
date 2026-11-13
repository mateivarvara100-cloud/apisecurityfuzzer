# Tests for the Phase 1 scanning framework: settings, path filling, the check registry, the
# auth-required check, the scan runner, report redaction, and the `scan` command end to end
# against a small local test server.

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from typer.testing import CliRunner

from apifuzz.checks import Check, ScanContext, all_checks, fill_path, select_checks
from apifuzz.checks.auth_required import AuthRequired
from apifuzz.cli import app
from apifuzz.endpoint_model import Endpoint, Parameter
from apifuzz.errors import AllowlistError
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Allowlist, Exchange, HttpClient, RecordedRequest, RecordedResponse
from apifuzz.report import REDACTED, redacted, to_json
from apifuzz.scanner import ScanResult, run_scan
from apifuzz.settings import ConfigError, Settings, load_dotenv, resolve_settings

runner = CliRunner()


# ---------------------------------------------------------------------------------------------
# settings


class TestSettings:
    # A CLI value beats the environment, which beats the spec's servers entry. The spec's server
    # is used only when the user confirmed that host (here through the allowlist).
    def test_precedence_flag_then_env_then_spec(self):
        spec = {"servers": [{"url": "http://from-spec:1"}]}
        env = {"APIFUZZ_BASE_URL": "http://from-env:2"}

        assert resolve_settings(spec=spec, env=env, base_url="http://flag:3").base_url == "http://flag:3"
        assert resolve_settings(spec=spec, env=env).base_url == "http://from-env:2"
        assert resolve_settings(spec=spec, env={"APIFUZZ_ALLOWLIST": "from-spec:1"}).base_url == "http://from-spec:1"

    # Swagger 2 specs give host + basePath + scheme instead of servers.
    def test_swagger_2_base_url(self):
        spec = {"swagger": "2.0", "host": "api.test:8080", "basePath": "/v1", "schemes": ["http"]}

        assert resolve_settings(spec=spec, allowlist=["api.test:8080"], env={}).base_url == "http://api.test:8080/v1"

    # No base URL anywhere is a clear configuration error.
    def test_missing_base_url_is_an_error(self):
        with pytest.raises(ConfigError, match="no base URL"):
            resolve_settings(spec={}, env={})

    # A base URL that isn't http(s) is refused.
    def test_non_http_base_url_is_an_error(self):
        with pytest.raises(ConfigError, match="http"):
            resolve_settings(base_url="ftp://x", env={})

    # The base URL's host is always on the allowlist; extra entries are added after it.
    def test_allowlist_always_includes_the_base_host(self):
        s = resolve_settings(base_url="http://localhost:8000/api/", env={"APIFUZZ_ALLOWLIST": "a.test, b.test:9"})

        assert s.base_url == "http://localhost:8000/api"  # trailing slash removed
        assert s.allowlist == ["localhost:8000", "a.test", "b.test:9"]

    # A "user@" in the base URL doesn't end up in the allowlist entry.
    def test_userinfo_is_not_put_in_the_allowlist(self):
        assert resolve_settings(base_url="http://u:p@localhost:8000", env={}).allowlist == ["localhost:8000"]

    # Tokens come from the env; empty strings count as "not set".
    def test_tokens_from_env(self):
        s = resolve_settings(base_url="http://x", env={"APIFUZZ_TOKEN_A": "aaa", "APIFUZZ_TOKEN_B": ""})

        assert (s.token_a, s.token_b) == ("aaa", None)

    # The .env reader skips comments, blanks and lines without "=", and strips one pair of quotes.
    def test_dotenv_parsing(self, tmp_path):
        path = tmp_path / ".env"
        path.write_text(
            '# comment\n\nAPIFUZZ_BASE_URL = http://x:1 \nAPIFUZZ_TOKEN_A="quoted"\nNOEQUALS\nEMPTY=\n',
            encoding="utf-8",
        )

        assert load_dotenv(path) == {"APIFUZZ_BASE_URL": "http://x:1", "APIFUZZ_TOKEN_A": "quoted", "EMPTY": ""}

    # A missing .env file is simply no values.
    def test_missing_dotenv_is_empty(self, tmp_path):
        assert load_dotenv(tmp_path / "nope.env") == {}


# ---------------------------------------------------------------------------------------------
# path filling and check selection


def _endpoint(path="/orders/{id}", method="GET", requires_auth=True, params=(("id", "integer"),)) -> Endpoint:
    return Endpoint(
        path=path,
        method=method,
        requires_auth=requires_auth,
        parameters=[Parameter(name=n, location="path", required=True, type=t) for n, t in params],
    )


class TestFillPath:
    # Integers get "1", strings get "test".
    def test_samples_by_type(self):
        e = _endpoint("/u/{uid}/f/{name}", params=(("uid", "integer"), ("name", "string")))

        assert fill_path(e) == "/u/1/f/test"

    # Given values win, and are URL-encoded so they stay inside one path segment.
    def test_given_values_are_encoded(self):
        assert fill_path(_endpoint(), {"id": "a/../b c"}) == "/orders/a%2F..%2Fb%20c"

    # A path with no placeholders is unchanged.
    def test_no_placeholders(self):
        assert fill_path(_endpoint("/me", params=())) == "/me"


class TestSelectChecks:
    # The defaults include auth-required.
    def test_defaults(self):
        assert "auth-required" in [c.id for c in select_checks()]

    # --skip removes a check; --only picks an exact set.
    def test_only_and_skip(self):
        assert [c.id for c in select_checks(only=["auth-required"])] == ["auth-required"]
        assert "auth-required" not in [c.id for c in select_checks(skip=["auth-required"])]

    # An unknown id is an error that lists the known ones.
    def test_unknown_id(self):
        with pytest.raises(KeyError, match="nope.*auth-required"):
            select_checks(only=["nope"])

    # Every registered check has an id and a description.
    def test_registered_checks_are_described(self):
        for cls in all_checks():
            assert cls.id and cls.description


# ---------------------------------------------------------------------------------------------
# the auth-required check, against a fake network


def _ctx(handler) -> ScanContext:
    settings = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"])
    client = HttpClient(Allowlist(settings.allowlist), transport=httpx.MockTransport(handler))
    return ScanContext(client, settings)


class TestAuthRequired:
    # A protected GET that answers 200 with no credentials is a HIGH finding with evidence.
    def test_open_protected_endpoint_is_reported(self):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"id": 1})

        (finding,) = AuthRequired().run(_endpoint(), _ctx(handler))

        assert finding.severity is Severity.HIGH
        assert finding.endpoint == "GET /orders/{id}"
        assert finding.evidence[0].request.url == "http://localhost:8000/orders/1"
        assert "authorization" not in seen[0].headers  # really sent without credentials

    # 401 and 403 are the right answers; 404 and 500 are inconclusive. None is a finding.
    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_other_statuses_are_not_findings(self, status):
        assert list(AuthRequired().run(_endpoint(), _ctx(lambda r: httpx.Response(status)))) == []

    # A 2xx that doesn't repeat on the confirmation request is not reported.
    def test_unconfirmed_result_is_not_reported(self):
        statuses = iter([200, 401])
        assert list(AuthRequired().run(_endpoint(), _ctx(lambda r: httpx.Response(next(statuses))))) == []

    # Endpoints that don't need a login, and unsafe methods, are never requested.
    @pytest.mark.parametrize("endpoint", [_endpoint(requires_auth=False), _endpoint(method="DELETE")])
    def test_skipped_endpoints_send_nothing(self, endpoint):
        sent = []

        assert list(AuthRequired().run(endpoint, _ctx(lambda r: sent.append(r) or httpx.Response(200)))) == []
        assert sent == []


# ---------------------------------------------------------------------------------------------
# the runner


class TestRunScan:
    # A network failure on one endpoint is recorded and the scan continues with the others.
    def test_request_error_is_recorded_and_scan_continues(self):
        def handler(request):
            if request.url.path == "/broken":
                raise httpx.ConnectError("refused")
            return httpx.Response(200)

        endpoints = [_endpoint("/broken", params=()), _endpoint("/open", params=())]

        result = run_scan(endpoints, [AuthRequired], _ctx(handler))

        assert [f.endpoint for f in result.findings] == ["GET /open"]
        assert len(result.errors) == 1 and "/broken" in result.errors[0]
        assert result.endpoints_scanned == 2

    # A refused host stops the whole scan instead of being swallowed.
    def test_allowlist_error_aborts(self):
        settings = Settings(base_url="http://evil.test", allowlist=["localhost:8000"])
        ctx = ScanContext(HttpClient(Allowlist(settings.allowlist), transport=httpx.MockTransport(lambda r: httpx.Response(200))), settings)

        with pytest.raises(AllowlistError):
            run_scan([_endpoint("/x", params=())], [AuthRequired], ctx)

    # run_scan returns findings worst first, whatever order the checks produced them in.
    def test_findings_sorted_by_severity(self):
        class Fake(Check):
            def run(self, endpoint, ctx):
                for severity in (Severity.LOW, Severity.CRITICAL, Severity.MEDIUM):
                    yield _finding(severity)

        result = run_scan([_endpoint()], [Fake], _ctx(lambda r: httpx.Response(200)))

        assert [f.severity for f in result.findings] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


# ---------------------------------------------------------------------------------------------
# reporting


def _finding(severity=Severity.HIGH) -> Finding:
    exchange = Exchange(
        request=RecordedRequest(
            method="GET", url="http://x/me", headers={"Authorization": "Bearer secret-a", "Accept": "*/*"}
        ),
        response=RecordedResponse(status_code=200, headers={"Set-Cookie": "sid=secret-s"}, body="{}"),
        elapsed_ms=1.0,
    )
    return Finding(check="t", severity=severity, title="t", endpoint="GET /me", detail="d", evidence=[exchange])


class TestReport:
    # Secret headers are replaced in both directions; other headers are kept.
    def test_redaction(self):
        result = ScanResult(findings=[_finding()])

        ex = redacted(result).findings[0].evidence[0]

        assert ex.request.headers == {"Authorization": REDACTED, "Accept": "*/*"}
        assert ex.response.headers == {"Set-Cookie": REDACTED}

    # Redaction works on a copy: the original result still holds the real values.
    def test_redaction_does_not_modify_the_original(self):
        result = ScanResult(findings=[_finding()])
        redacted(result)

        assert result.findings[0].evidence[0].request.headers["Authorization"] == "Bearer secret-a"

    # The JSON report contains no secrets and writes severities by name.
    def test_json_report(self):
        text = to_json(ScanResult(findings=[_finding()]))

        assert "secret-a" not in text and "secret-s" not in text
        assert json.loads(text)["findings"][0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------------------------
# `apifuzz scan` end to end, against a real local HTTP server


class _VulnShopHandler(BaseHTTPRequestHandler):
    """/me checks for a token (correct). /orders/{id} forgets to (the planted bug)."""

    def do_GET(self):  # noqa: N802 (name required by BaseHTTPRequestHandler)
        if self.path == "/me":
            status = 200 if self.headers.get("Authorization") else 401
        elif self.path.startswith("/orders/"):
            status = 200  # BUG: no auth check
        elif self.path.startswith("/search"):
            status = 200  # public by design
        else:
            status = 404
        body = b'{"ok": true}' if status == 200 else b'{"error": "no"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.fixture
def local_api():
    # Port 0 asks the OS for any free port; the server only listens on 127.0.0.1.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnShopHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


class TestScanCommand:
    # Without --i-have-authorization nothing is sent and the command exits 2.
    def test_requires_authorization_flag(self, sample_spec_path, local_api):
        result = runner.invoke(app, ["scan", str(sample_spec_path), "--base-url", local_api])

        assert result.exit_code == 2
        assert "--i-have-authorization" in result.output

    # The planted bug is found, the correctly protected route isn't flagged, and the exit code is 1.
    def test_finds_the_open_endpoint(self, sample_spec_path, local_api, monkeypatch):
        monkeypatch.delenv("APIFUZZ_BASE_URL", raising=False)
        result = runner.invoke(
            app,
            ["scan", str(sample_spec_path), "--i-have-authorization", "--base-url", local_api, "--json",
             "--only", "auth-required"],
        )

        assert result.exit_code == 1, result.output
        report = json.loads(result.stdout)
        assert [f["endpoint"] for f in report["findings"]] == ["GET /orders/{id}"]
        assert report["findings"][0]["evidence"][0]["request"]["url"] == f"{local_api}/orders/1"
        assert report["errors"] == []

    # --fail-on never always exits 0, even with findings.
    def test_fail_on_never(self, sample_spec_path, local_api):
        result = runner.invoke(
            app,
            ["scan", str(sample_spec_path), "--i-have-authorization", "--base-url", local_api, "--fail-on", "never"],
        )

        assert result.exit_code == 0, result.output
        assert "GET /orders/{id}" in result.stdout

    # Filters limit what is scanned: only /me is checked, and it's protected, so nothing is found.
    def test_filters_apply_to_scan(self, sample_spec_path, local_api):
        result = runner.invoke(
            app,
            ["scan", str(sample_spec_path), "--i-have-authorization", "--base-url", local_api, "-p", "/me", "--json"],
        )

        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout)
        assert report["findings"] == [] and report["endpoints_scanned"] == 1

    # An unknown --only id is a usage error naming the known checks.
    def test_unknown_check_id(self, sample_spec_path):
        result = runner.invoke(app, ["scan", str(sample_spec_path), "--i-have-authorization", "--only", "nope"])

        assert result.exit_code == 2
        assert "auth-required" in result.output

    # No base URL from any source is a clean error, not a traceback.
    def test_missing_base_url(self, sample_spec_path, monkeypatch, tmp_path):
        monkeypatch.delenv("APIFUZZ_BASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)  # so a real .env in the project can't supply one
        result = runner.invoke(app, ["scan", str(sample_spec_path), "--i-have-authorization"])

        assert result.exit_code == 2
        assert "no base URL" in result.output
        assert "Traceback" not in result.output

    # A server that isn't running is an error (exit 2), not a clean report: nothing was tested.
    def test_unreachable_target_is_an_error(self, sample_spec_path):
        result = runner.invoke(
            app,
            ["scan", str(sample_spec_path), "--i-have-authorization", "--base-url", "http://127.0.0.1:1", "--timeout", "2"],
        )

        assert result.exit_code == 2, result.output
        assert "nothing was tested" in result.output
        assert "Traceback" not in result.output

    # `apifuzz checks` lists the registered checks.
    def test_checks_command(self):
        result = runner.invoke(app, ["checks"])

        assert result.exit_code == 0
        assert "auth-required" in result.stdout
