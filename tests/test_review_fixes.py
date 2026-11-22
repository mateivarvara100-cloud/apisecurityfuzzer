"""Tests for the fixes from the review after Phase 1.

Each class covers one way the Phase 1 scanner could mislead: a clean report for an API it never
tested, a target chosen by a document, a report that leaks data, or a silent skip.
"""

import json
import time
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import apifuzz.cli as cli
from apifuzz import __version__
from apifuzz.checks import ScanContext, select_checks
from apifuzz.endpoint_model import Endpoint, build_endpoints
from apifuzz.errors import DockerVerifyError, RequestLimitError, SessionError
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Allowlist, Exchange, HttpClient, RecordedRequest, RecordedResponse
from apifuzz.report import REDACTED, redacted, to_html, to_json
from apifuzz.scanner import ScanResult, run_scan
from apifuzz.session_manager import authenticate, preflight
from apifuzz.settings import ConfigError, Settings, resolve_settings
from apifuzz.spec_loader import load_spec

ROOT = Path(__file__).resolve().parent.parent
LAB_SPEC = ROOT / "lab" / "openapi.json"
runner = CliRunner()

ME = Endpoint(path="/me", method="GET", requires_auth=True)
ORDERS = Endpoint(path="/orders", method="GET", requires_auth=True)


def _client(handler, **kw) -> HttpClient:
    return HttpClient(Allowlist(["localhost:8000"]), transport=httpx.MockTransport(handler), **kw)


def _settings(**kw) -> Settings:
    return Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"], **kw)


# ---------------------------------------------------------------------------------------------
# preflight: the test accounts are checked before the scan relies on them


class TestPreflight:
    # The same token for A and B would make every object "readable by both accounts".
    def test_same_token_is_refused(self):
        with pytest.raises(SessionError, match="same token"):
            preflight(_client(lambda r: pytest.fail("sent a request")), _settings(token_a="t", token_b="t"), [ME])

    # A token every protected endpoint refuses is expired or wrong: stop, don't report "clean".
    @pytest.mark.parametrize("status", [401, 403])
    def test_dead_token_is_refused(self, status):
        with pytest.raises(SessionError, match=rf"account A's token was refused.*HTTP {status}"):
            preflight(_client(lambda r: httpx.Response(status)), _settings(token_a="old", token_b="b"), [ME, ORDERS])

    # Two different tokens that belong to one user are caught on a "who am I" endpoint.
    def test_same_user_behind_two_tokens_is_refused(self):
        with pytest.raises(SessionError, match="same user"):
            preflight(_client(lambda r: httpx.Response(200, json={"id": 1})), _settings(token_a="a", token_b="b"), [ME])

    # Working tokens for two users pass quietly, with one request each.
    def test_two_working_accounts_pass(self):
        sent = []

        def handler(request):
            sent.append(request.headers["authorization"])
            return httpx.Response(200, json={"id": 1 if request.headers["authorization"].endswith("a") else 2})

        assert preflight(_client(handler), _settings(token_a="a", token_b="b"), [ORDERS, ME]) == []
        assert sent == ["Bearer a", "Bearer b"]

    # A 403 on one endpoint (an admin page, say) is not a verdict if another endpoint accepts the token.
    def test_one_refusal_is_not_a_dead_token(self):
        def handler(request):
            return httpx.Response(403) if request.url.path == "/me" else httpx.Response(200, json=[])

        assert preflight(_client(handler), _settings(token_a="a"), [ME, ORDERS]) == []

    # When nothing can confirm a token, the user is told rather than left guessing.
    def test_unconfirmed_token_is_a_warning(self):
        (warning,) = preflight(_client(lambda r: pytest.fail("sent a request")), _settings(token_a="a"), [])
        assert "could not confirm account A" in warning
        (warning,) = preflight(_client(lambda r: httpx.Response(500)), _settings(token_a="a"), [ME])
        assert "could not confirm account A" in warning

    # Against the real lab: the same lab token twice stops the scan instead of a false CRITICAL.
    def test_cli_refuses_the_same_account_twice(self, lab_api, clean_env):
        clean_env.setenv("APIFUZZ_TOKEN_A", "lab-token-alice")
        clean_env.setenv("APIFUZZ_TOKEN_B", "lab-token-alice")
        clean_env.setenv("LAB_HARDENED", "1")

        result = runner.invoke(cli.app, ["scan", str(LAB_SPEC), "--i-have-authorization", "--base-url", lab_api, "--json"])

        assert result.exit_code == 2
        assert "same token" in result.output and "CRITICAL" not in result.output

    # Against the real lab: an expired token stops the scan instead of reporting "0 findings".
    def test_cli_refuses_a_dead_token(self, lab_api, clean_env):
        clean_env.setenv("APIFUZZ_TOKEN_A", "expired-token")
        clean_env.setenv("APIFUZZ_TOKEN_B", "lab-token-bob")

        result = runner.invoke(cli.app, ["scan", str(LAB_SPEC), "--i-have-authorization", "--base-url", lab_api])

        assert result.exit_code == 2
        assert "account A's token was refused" in result.output


# ---------------------------------------------------------------------------------------------
# logging in and sending the token the way the API expects


class TestAuthSchemes:
    # Credentials can be sent as form fields with custom names (e.g. an OAuth2 password login).
    def test_form_login_with_custom_fields(self):
        seen = {}

        def handler(request):
            seen["type"] = request.headers["content-type"]
            seen["body"] = request.content.decode()
            return httpx.Response(200, json={"access_token": "tok"})

        s = authenticate(
            _client(handler),
            _settings(user_a="al@x.test", password_a="pw", login_format="form", login_user_field="email"),
        )

        assert s.token_a == "tok"
        assert seen["type"] == "application/x-www-form-urlencoded"
        assert seen["body"] == "email=al%40x.test&password=pw"

    def test_login_settings_come_from_the_env(self):
        s = resolve_settings(
            base_url="http://x",
            env={"APIFUZZ_LOGIN_FORMAT": "FORM", "APIFUZZ_LOGIN_USER_FIELD": "email", "APIFUZZ_SHARED": "/posts/*, /tags/*"},
        )
        assert (s.login_format, s.login_user_field, s.login_password_field) == ("form", "email", "password")
        assert s.shared_paths == ["/posts/*", "/tags/*"]
        with pytest.raises(ConfigError, match="json or form"):
            resolve_settings(base_url="http://x", env={"APIFUZZ_LOGIN_FORMAT": "xml"})

    # The spec's security scheme decides how the token is sent.
    @pytest.mark.parametrize(
        "scheme, expected",
        [
            ({"type": "http", "scheme": "bearer"}, {"Authorization": "Bearer tok"}),
            ({"type": "apiKey", "in": "header", "name": "X-API-Key"}, {"X-API-Key": "tok"}),
            ({"type": "apiKey", "in": "cookie", "name": "session"}, {"Cookie": "session=tok"}),
            ({"type": "oauth2", "flows": {}}, {"Authorization": "Bearer tok"}),
        ],
    )
    def test_scheme_from_the_spec(self, scheme, expected):
        spec = {"security": [{"main": []}], "components": {"securitySchemes": {"other": {"type": "http"}, "main": scheme}}}
        assert resolve_settings(spec=spec, base_url="http://x", env={}).auth_headers("tok") == expected

    # Swagger 2 keeps its schemes under securityDefinitions.
    def test_swagger_2_scheme(self):
        spec = {"swagger": "2.0", "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-Token"}}}
        assert resolve_settings(spec=spec, base_url="http://x", env={}).auth_headers("tok") == {"X-Token": "tok"}

    # The env overrides the spec; a word such as "Token" is followed by a space.
    def test_env_overrides_the_scheme(self):
        s = resolve_settings(base_url="http://x", env={"APIFUZZ_AUTH_PREFIX": "Token"})
        assert s.auth_headers("tok") == {"Authorization": "Token tok"}
        s = resolve_settings(base_url="http://x", env={"APIFUZZ_AUTH_HEADER": "X-Auth"})
        assert s.auth_headers("tok") == {"X-Auth": "tok"}


# ---------------------------------------------------------------------------------------------
# a spec may not choose the target on its own


class TestSpecCannotChooseTheTarget:
    SPEC = {"servers": [{"url": "https://someone-else.example/v1"}]}

    # A spec that names some host is not enough to scan it (and send it the test tokens).
    @pytest.mark.parametrize("source", ["openapi.json", "https://docs.example/openapi.json", None])
    def test_unconfirmed_server_is_refused(self, source):
        with pytest.raises(ConfigError, match="may not choose the target"):
            resolve_settings(spec=self.SPEC, spec_source=source, env={"APIFUZZ_TOKEN_A": "secret"})

    # An API describing itself is fine: the spec came from the same host and port.
    def test_server_matching_the_spec_url_is_accepted(self):
        s = resolve_settings(spec=self.SPEC, spec_source="https://someone-else.example/openapi.json", env={})
        assert s.base_url == "https://someone-else.example/v1"
        with pytest.raises(ConfigError):  # same host, other port: a different service
            resolve_settings(spec=self.SPEC, spec_source="https://someone-else.example:8443/openapi.json", env={})

    # Naming the host in --allow, or passing the URL as --base-url, confirms it.
    def test_the_user_can_confirm_the_server(self):
        assert resolve_settings(spec=self.SPEC, allowlist=["someone-else.example"], env={}).allowlist == ["someone-else.example"]
        assert resolve_settings(spec=self.SPEC, base_url="https://someone-else.example/v1", env={}).base_url.endswith("/v1")

    # A relative server ("/api/v1") is relative to where the spec was downloaded from.
    def test_relative_server(self):
        spec = {"servers": [{"url": "/api/v1"}]}
        s = resolve_settings(spec=spec, spec_source="http://localhost:8000/docs/openapi.json", env={})
        assert s.base_url == "http://localhost:8000/api/v1"
        with pytest.raises(ConfigError, match="relative path"):
            resolve_settings(spec=spec, spec_source="openapi.json", env={})

    def test_cli_refuses_a_spec_chosen_target(self, write_spec, clean_env):
        spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}, **self.SPEC}
        result = runner.invoke(cli.app, ["scan", write_spec(spec), "--i-have-authorization"])
        assert result.exit_code == 2
        assert "may not choose the target" in result.output

    # In Docker-only mode the spec URL itself must be a verified container, before it is fetched.
    def test_docker_only_checks_the_spec_url_before_downloading(self, clean_env):
        def refuse(target, extras):
            raise DockerVerifyError(f"{target}: not a container")

        clean_env.setattr(cli, "verify_targets", refuse)
        clean_env.setattr(cli, "load_spec", lambda *a, **k: pytest.fail("the spec was downloaded"))

        result = runner.invoke(
            cli.app, ["scan", "http://elsewhere.test/openapi.json", "--i-have-authorization", "--require-docker"]
        )

        assert result.exit_code == 2
        assert "not a container" in result.output

    # A redirected spec download can be refused (Docker-only mode does this).
    def test_spec_redirects_can_be_refused(self):
        from apifuzz.errors import SpecError

        transport = httpx.MockTransport(lambda r: httpx.Response(302, headers={"Location": "http://other.test/x"}))
        with httpx.Client(transport=transport, follow_redirects=False) as client, pytest.raises(SpecError, match="HTTP 302"):
            load_spec("http://localhost:8000/openapi.json", client=client)


# ---------------------------------------------------------------------------------------------
# the scanner identifies and limits itself


class TestClientLimits:
    def test_user_agent_names_the_tool(self):
        ex = _client(lambda r: httpx.Response(200)).request("GET", "http://localhost:8000/x")
        assert ex.request.headers["user-agent"] == f"apifuzz/{__version__}"

    def test_request_limit(self):
        client = _client(lambda r: httpx.Response(200), max_requests=2)
        client.request("GET", "http://localhost:8000/1")
        client.request("GET", "http://localhost:8000/2")
        with pytest.raises(RequestLimitError, match="request limit reached"):
            client.request("GET", "http://localhost:8000/3")
        assert (client.requests_sent, client.responses_received) == (2, 2)

    # Hitting the limit keeps what was found, but the result says the scan is partial.
    def test_scan_stops_at_the_limit_and_says_so(self):
        endpoints = [Endpoint(path=f"/e{i}", method="GET", requires_auth=True) for i in range(5)]
        client = _client(lambda r: httpx.Response(200), max_requests=4)

        result = run_scan(endpoints, select_checks(only=["auth-required"]), ScanContext(client, _settings()))

        assert result.incomplete and "stopped early" in result.errors[-1]
        assert len(result.findings) == 2 and result.requests_sent == 4

    # A failed request counts as sent but not answered, which is how "target is down" is noticed.
    def test_unanswered_requests_are_counted(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        client = _client(handler)
        result = run_scan([ME], select_checks(only=["auth-required"]), ScanContext(client, _settings()))
        assert (client.requests_sent, client.responses_received) == (1, 0)
        assert result.coverage[0].not_tested == 1


# ---------------------------------------------------------------------------------------------
# coverage: "not tested" must never look like "safe"


class TestCoverage:
    def test_each_check_reports_what_it_tested(self):
        endpoints = [
            ME,  # 401: tested
            Endpoint(path="/missing", method="GET", requires_auth=True),  # 404: can't tell
            Endpoint(path="/open", method="GET", requires_auth=False),  # not applicable
        ]

        def handler(request):
            return httpx.Response(401 if request.url.path == "/me" else 404)

        result = run_scan(endpoints, select_checks(only=["auth-required"]), ScanContext(_client(handler), _settings()))

        (coverage,) = result.coverage
        assert (coverage.tested, coverage.not_tested, coverage.not_applicable) == (1, 1, 1)
        assert coverage.notes == ["GET /missing: answered HTTP 404 to the sample request, which settles nothing"]
        assert result.target == "http://localhost:8000" and result.requests_sent == 2
        page = to_html(result)
        assert "What was tested" in page and "GET /missing" in page

    # The report carries what a reader needs to compare two runs.
    def test_report_metadata_and_fingerprints(self):
        finding = Finding(check="bola", severity=Severity.HIGH, title="t", endpoint="GET /orders/{id}", detail="d")
        report = json.loads(to_json(ScanResult(findings=[finding], target="http://x")))

        assert report["schema_version"] == 2 and report["tool_version"] == __version__
        assert report["findings"][0]["fingerprint"] == finding.fingerprint
        same = Finding(check="bola", severity=Severity.LOW, title="other words", endpoint="GET /orders/{id}", detail="x")
        other = Finding(check="bola", severity=Severity.HIGH, title="t", endpoint="GET /orders/{id}", detail="d", key="role")
        assert same.fingerprint == finding.fingerprint  # wording and severity may change between versions
        assert other.fingerprint != finding.fingerprint


# ---------------------------------------------------------------------------------------------
# redaction: a report can be shared


def _result(url="http://x/orders/2", req_headers=None, req_body=None, res_body="", errors=()) -> ScanResult:
    ex = Exchange(
        request=RecordedRequest(method="GET", url=url, headers=req_headers or {}, body=req_body),
        response=RecordedResponse(status_code=200, headers={}, body=res_body),
        elapsed_ms=1.0,
    )
    finding = Finding(check="bola", severity=Severity.CRITICAL, title="t", endpoint="GET /orders/{id}", detail="d", evidence=[ex])
    return ScanResult(findings=[finding], errors=list(errors))


class TestRedaction:
    # Another user's personal fields are masked, at any depth; the rest of the object stays readable.
    def test_personal_fields_in_bodies_are_masked(self):
        body = json.dumps({"id": 2, "item": "lamp", "email": "bob@lab.test", "profile": {"phone": "555", "apiToken": "xyz"}})
        shown = json.loads(redacted(_result(res_body=body)).findings[0].evidence[0].response.body)

        assert shown == {"id": 2, "item": "lamp", "email": REDACTED, "profile": {"phone": REDACTED, "apiToken": REDACTED}}

    # E-mail addresses are masked even in text that isn't JSON.
    def test_emails_in_plain_text_are_masked(self):
        shown = redacted(_result(res_body="contact bob@lab.test now")).findings[0].evidence[0].response.body
        assert shown == f"contact {REDACTED} now"

    # A hostile API's answer can't stall redaction: 64 KB with no "@" took about 12 s before.
    def test_email_masking_is_fast_on_a_long_answer(self):
        start = time.perf_counter()
        redacted(_result(res_body="a" * 65_536 + " bob@lab.test"))
        assert time.perf_counter() - start < 1

    # A token is replaced wherever it appears, not only in the Authorization header.
    def test_tokens_are_replaced_everywhere(self):
        result = _result(
            url="http://x/orders/2?access=tok-secret-1",
            req_headers={"X-Api-Token": "tok-secret-1"},
            req_body="note=tok-secret-1",
            res_body='{"echo": "tok-secret-1"}',
            errors=["bola on GET /x: GET http://x/?k=tok-secret-1: timed out"],
        )
        text = to_json(result, secrets=["tok-secret-1", None, "ab"])  # too-short secrets are ignored

        assert "tok-secret-1" not in text and text.count(REDACTED) == 5
        assert "tok-secret-1" in to_json(result, redact=False, secrets=["tok-secret-1"])

    # Long bodies are cut to an excerpt: enough to see the object's shape, not a data dump.
    def test_bodies_are_shortened(self):
        shown = redacted(_result(res_body="x" * 5000)).findings[0].evidence[0].response.body
        assert len(shown) < 700 and shown.endswith("[shortened]")

    def test_redaction_does_not_modify_the_original(self):
        result = _result(res_body='{"email": "bob@lab.test"}')
        redacted(result, secrets=["whatever-secret"])
        assert "bob@lab.test" in result.findings[0].evidence[0].response.body


# ---------------------------------------------------------------------------------------------
# the lab: ground truth for the fixes


def _lab_scan(base, *extra):
    return runner.invoke(cli.app, ["scan", str(LAB_SPEC), "--i-have-authorization", "--base-url", base, *extra])


@pytest.fixture
def lab_accounts(clean_env):
    for k, v in {"USER_A": "alice", "PASSWORD_A": "alice", "USER_B": "bob", "PASSWORD_B": "bob"}.items():
        clean_env.setenv(f"APIFUZZ_{k}", v)
    return clean_env


CATALOG_NOTE = "GET /catalog/{name}: neither account could read any of the 4 ids tried, so there was nothing to compare"


class TestLab:
    # Every operation in the lab's spec is really served by the lab app (the spec is hand-written).
    def test_spec_and_app_agree(self, lab_api):
        endpoints = build_endpoints(load_spec(str(LAB_SPEC)))
        assert len(endpoints) >= 10
        with httpx.Client(base_url=lab_api, headers={"Authorization": "Bearer lab-token-alice"}) as client:
            for e in endpoints:
                response = client.request(e.method, e.path.replace("{id}", "1"), json={} if e.method != "GET" else None)
                assert response.json() != {"error": "not found"}, f"{e.method} {e.path} is in the spec but not in the app"

    # ...and every route the app serves is in the spec, so nothing in the lab goes unscanned.
    def test_app_routes_are_in_the_spec(self):
        import re

        source = (ROOT / "lab" / "app.py").read_text(encoding="utf-8")
        exact = set(re.findall(r'path == "(/[^"]*)"', source))
        prefixes = {p.rstrip("/") + "/{id}" for p in re.findall(r'path\.startswith\("(/[^"]*/)"\)', source)}
        served = (exact | prefixes) - {"/health", "/openapi.json"}  # the two that are not part of the API
        # The app's source doesn't say what a placeholder is called, so compare them as "{id}".
        in_spec = {re.sub(r"\{[^}]+\}", "{id}", e.path) for e in build_endpoints(load_spec(str(LAB_SPEC)))}

        assert served and served == in_spec

    # The catalog is shared and invoices are protected: neither may be reported, and both count
    # as tested. The planted order flaw is proven by the "my orders" listing, so it is CRITICAL.
    def test_bola_guards_stay_quiet(self, lab_api, lab_accounts, tmp_path):
        out = tmp_path / "scan.json"
        result = _lab_scan(lab_api, "--only", "bola", "--json-out", str(out), "--fail-on", "never")

        assert result.exit_code == 0, result.output
        report = json.loads(out.read_text(encoding="utf-8"))
        (finding,) = report["findings"]
        assert (finding["endpoint"], finding["severity"]) == ("GET /orders/{id}", "CRITICAL")
        assert "GET /orders lists this id only for account" in finding["detail"]
        (coverage,) = report["coverage"]
        # orders, invoices, products, and users (open to everyone: auth-required's finding, not bola's).
        # The catalog is looked up by name, and no name is known to either account: not tested, said so.
        assert coverage["tested"] == 4
        assert coverage["notes"] == [CATALOG_NOTE]
        assert "What was tested" in result.output  # the table is still printed next to --json-out
        # The evidence shows Bob's order to Alice, but not the tokens.
        assert "lab-token" not in out.read_text(encoding="utf-8")

    # Marking a path as shared skips it, and the report says so.
    def test_shared_paths_are_skipped_and_listed(self, lab_api, lab_accounts):
        result = _lab_scan(lab_api, "--only", "bola", "--shared", "/orders/*", "--json")

        report = json.loads(result.stdout)
        assert report["findings"] == []
        assert report["coverage"][0]["notes"] == ["GET /orders/{id}: marked as shared on purpose (--shared)", CATALOG_NOTE]

    # A low request limit stops the scan with exit 2 before it starts, or marks it partial.
    def test_request_limit_from_the_cli(self, lab_api, lab_accounts):
        result = _lab_scan(lab_api, "--max-requests", "12", "--json")

        report = json.loads(result.stdout)
        assert report["incomplete"] is True and report["requests_sent"] == 12
        assert any("stopped early" in line for line in report["errors"])
