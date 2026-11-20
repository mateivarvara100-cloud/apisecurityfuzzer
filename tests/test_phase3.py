"""Phase 3: SARIF output and the file of accepted findings (what makes the scanner usable in CI)."""

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import apifuzz.cli as cli
from apifuzz import __version__
from apifuzz.accepted import AcceptedFileError, apply_accepted, load_accepted, write_accepted
from apifuzz.errors import AllowlistError, SpecError
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Allowlist
from apifuzz.report import findings_table, headline, to_html
from apifuzz.sarif import _operation_line, to_sarif
from apifuzz.scanner import ScanResult
from apifuzz.spec_loader import load_spec

ROOT = Path(__file__).resolve().parent.parent
LAB_SPEC = ROOT / "lab" / "openapi.json"
runner = CliRunner()


def _finding(check="bola", severity=Severity.CRITICAL, endpoint="GET /orders/{id}", **extra) -> Finding:
    return Finding(check=check, severity=severity, title="t", endpoint=endpoint, detail="d", **extra)


def _flat(text: str) -> str:
    """Console output on one line. The terminal wraps long lines (a temp path can be over 100
    character   s), so a phrase must not be looked for in the raw output."""
    return " ".join(text.split())


def _lab_scan(base, *extra):
    return runner.invoke(cli.app, ["scan", str(LAB_SPEC), "--i-have-authorization", "--base-url", base, *extra])


@pytest.fixture
def lab_accounts(clean_env):
    for k, v in {"USER_A": "alice", "PASSWORD_A": "alice", "USER_B": "bob", "PASSWORD_B": "bob"}.items():
        clean_env.setenv(f"APIFUZZ_{k}", v)
    return clean_env


# ---------------------------------------------------------------------------------------------
# SARIF


class TestSarif:
    def _doc(self, result, spec=str(LAB_SPEC), **kwargs):
        return json.loads(to_sarif(result, spec, **kwargs))

    # The document has the shape SARIF 2.1.0 requires: version, one run, a tool with rules, results.
    def test_document_shape(self):
        result = ScanResult(findings=[_finding()], checks_run=["auth-required", "bola"], tool_version="1.2.3")

        doc = self._doc(result)

        assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
        (run,) = doc["runs"]
        driver = run["tool"]["driver"]
        assert (driver["name"], driver["version"]) == ("apifuzz", "1.2.3")
        assert [r["id"] for r in driver["rules"]] == ["auth-required", "bola"]  # every check that ran
        (res,) = run["results"]
        assert res["ruleId"] == "bola" and driver["rules"][res["ruleIndex"]]["id"] == "bola"
        assert res["partialFingerprints"] == {"apifuzzFingerprint/v1": result.findings[0].fingerprint}
        assert res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "GET /orders/{id}"

    # Severity maps to SARIF's level, and to the score GitHub uses for critical/high/medium/low.
    @pytest.mark.parametrize(
        "severity, level, score",
        [(Severity.CRITICAL, "error", "9.5"), (Severity.HIGH, "error", "8.0"), (Severity.MEDIUM, "warning", "5.5"),
         (Severity.LOW, "note", "3.0"), (Severity.INFO, "note", "1.0")],
    )
    def test_severity_mapping(self, severity, level, score):
        run = self._doc(ScanResult(findings=[_finding(severity=severity)], checks_run=["bola"]))["runs"][0]

        assert run["results"][0]["level"] == level
        assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == score

    # A rule's score is the worst severity its check reported; a check with no findings has none.
    def test_rule_score_is_the_worst_finding(self):
        findings = [_finding("rate-limit", Severity.MEDIUM, "GET /search"), _finding("rate-limit", Severity.HIGH, "POST /login")]
        rules = self._doc(ScanResult(findings=findings, checks_run=["bola", "rate-limit"]))["runs"][0]["tool"]["driver"]["rules"]

        assert "security-severity" not in rules[0]["properties"]
        assert rules[1]["properties"]["security-severity"] == "8.0"
        assert "API4:2023" in rules[1]["properties"]["tags"]

    # Each result points at the operation's line in the spec, named relative to where the scan runs.
    def test_points_at_the_operation_in_the_spec(self, monkeypatch):
        monkeypatch.chdir(ROOT)
        res = self._doc(ScanResult(findings=[_finding(endpoint="GET /search")], checks_run=["bola"]))["runs"][0]["results"][0]

        location = res["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "lab/openapi.json"
        lines = LAB_SPEC.read_text(encoding="utf-8").splitlines()
        line = location["region"]["startLine"]
        assert '"get"' in lines[line - 1]
        assert any('"/search"' in text for text in lines[:line])  # ...and it is the one under /search

    # YAML specs are searched the same way; an endpoint that isn't in the text falls back to line 1.
    def test_operation_line_in_yaml(self):
        lines = ["paths:", "  /orders:", "    post:", "      summary: x", "  /orders/{id}:", "    get:", "    delete:"]

        assert _operation_line(lines, "DELETE /orders/{id}") == 7
        assert _operation_line(lines, "POST /orders") == 3
        assert _operation_line(lines, "GET /orders") == 2  # the path exists, the method doesn't: the path's line
        assert _operation_line(lines, "GET /nope") == 1

    # A spec given as a URL is named by its file name, and everything points at line 1.
    def test_spec_from_a_url(self):
        res = self._doc(ScanResult(findings=[_finding()]), spec="https://api.example.com/v1/openapi.json")["runs"][0]["results"][0]

        location = res["locations"][0]["physicalLocation"]
        assert location == {"artifactLocation": {"uri": "openapi.json"}, "region": {"startLine": 1}}

    # An accepted finding is carried as a suppression with its reason.
    def test_accepted_finding_is_suppressed(self):
        result = ScanResult(findings=[_finding(accepted=True, accepted_reason="behind the gateway"), _finding("rate-limit")])

        accepted, still_open = self._doc(result)["runs"][0]["results"]

        assert accepted["suppressions"] == [{"kind": "external", "justification": "behind the gateway"}]
        assert "suppressions" not in still_open

    # Tokens never reach the file, and a partial scan is marked as not successful.
    def test_secrets_and_partial_scans(self):
        finding = _finding()
        finding.detail = "sent Bearer secret-token-123"
        result = ScanResult(findings=[finding], errors=["scan stopped early: secret-token-123"], incomplete=True)

        text = to_sarif(result, str(LAB_SPEC), secrets=["secret-token-123", None])

        assert "secret-token-123" not in text
        invocation = json.loads(text)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["message"]["text"] == "scan stopped early: [redacted]"


# ---------------------------------------------------------------------------------------------
# accepted findings


class TestAcceptedFile:
    def _write(self, tmp_path, content) -> Path:
        path = tmp_path / "accepted.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def test_load(self, tmp_path):
        path = self._write(tmp_path, {"accepted": [{"fingerprint": "abc", "check": "bola", "reason": " known "}]})

        assert load_accepted(path) == {"abc": "known"}

    # Every way the file can be wrong is an error that names the file, not a silent empty list.
    @pytest.mark.parametrize(
        "content, message",
        [
            ("{not json", "not valid JSON"),
            ([], 'must be an object with an "accepted" list'),
            ({"accepted": [{"reason": "x"}]}, "entry 1 has no fingerprint"),
            ({"accepted": [{"fingerprint": "abc", "check": "bola", "endpoint": "GET /x", "reason": " "}]},
             r"entry 1 \(bola on GET /x\) has no reason"),
        ],
    )
    def test_bad_files(self, tmp_path, content, message):
        with pytest.raises(AcceptedFileError, match=message):
            load_accepted(self._write(tmp_path, content))

    def test_missing_file(self, tmp_path):
        with pytest.raises(AcceptedFileError, match="could not read"):
            load_accepted(tmp_path / "nope.json")

    # Matching findings are marked; fingerprints that match nothing come back as stale.
    def test_apply(self):
        hit, miss = _finding(), _finding("rate-limit")

        stale = apply_accepted([hit, miss], {hit.fingerprint: "why", "gone": "old"})

        assert (hit.accepted, hit.accepted_reason, miss.accepted) == (True, "why", False)
        assert stale == ["gone"]

    # The starting file lists every finding with an empty reason, so it can't be used as it is.
    def test_written_file_needs_reasons(self, tmp_path):
        path = tmp_path / "accepted.json"

        write_accepted(path, [_finding(), _finding("rate-limit", accepted=True, accepted_reason="kept")])

        entries = json.loads(path.read_text(encoding="utf-8"))["accepted"]
        assert [(e["check"], e["reason"]) for e in entries] == [("bola", ""), ("rate-limit", "kept")]
        with pytest.raises(AcceptedFileError, match="has no reason"):
            load_accepted(path)


class TestAcceptedInReports:
    RESULT = ScanResult(
        endpoints_scanned=3,
        findings=[_finding(), _finding("rate-limit", Severity.MEDIUM, "GET /search", accepted=True, accepted_reason="gateway")],
    )

    # The headline counts open findings and mentions the accepted ones apart.
    def test_headline(self):
        assert headline(self.RESULT) == "3 endpoints scanned · 1 finding (1 critical) · 1 accepted"

    def test_html_has_an_accepted_group(self):
        page = to_html(self.RESULT)

        assert "Accepted (1)" in page and "<strong>Accepted:</strong> gateway" in page
        assert "Medium (1)" not in page  # the accepted finding is not listed under its severity

    def test_table_lists_accepted_last(self):
        table = findings_table(self.RESULT)

        severities = [str(cell) for cell in table.columns[0].cells]
        assert severities == ["CRITICAL", "MEDIUM\naccepted"]


# ---------------------------------------------------------------------------------------------
# through the CLI, against the real lab app


class TestCli:
    # --sarif writes a file with exactly the lab's planted findings, and no tokens.
    def test_sarif_of_the_lab(self, lab_api, lab_accounts, tmp_path):
        out = tmp_path / "scan.sarif"

        result = _lab_scan(lab_api, "--sarif", str(out), "--fail-on", "never")

        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        run = json.loads(text)["runs"][0]
        assert run["tool"]["driver"]["version"] == __version__
        assert {(r["ruleId"], r["properties"]["endpoint"]) for r in run["results"]} == {
            ("bola", "GET /orders/{id}"), ("auth-required", "GET /users/{id}"), ("mass-assignment", "PATCH /users/{id}"),
            ("rate-limit", "POST /login"), ("rate-limit", "GET /search"),
            ("injection", "GET /search"), ("injection", "POST /login"),
            ("injection", "GET /catalog/{name}"), ("injection", "GET /stock"),
        }
        assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] > 1 for r in run["results"])
        assert "lab-token" not in text

    # The whole loop: write the file, give reasons, and the same scan no longer fails.
    def test_accepting_everything_turns_the_run_green(self, lab_api, lab_accounts, tmp_path):
        accepted = tmp_path / "accepted.json"
        first = _lab_scan(lab_api, "--write-accepted", str(accepted))
        assert first.exit_code == 1  # findings at or above --fail-on

        # Without reasons the file is refused before any request is sent.
        refused = _lab_scan(lab_api, "--accepted", str(accepted))
        assert refused.exit_code == 2 and "has no reason" in _flat(refused.output)

        data = json.loads(accepted.read_text(encoding="utf-8"))
        for entry in data["accepted"]:
            entry["reason"] = "planted on purpose in the lab"
        accepted.write_text(json.dumps(data), encoding="utf-8")

        second = _lab_scan(lab_api, "--accepted", str(accepted), "--json")
        assert second.exit_code == 0, second.output
        report = json.loads(second.stdout)
        assert len(report["findings"]) == 9 and all(f["accepted"] for f in report["findings"])

    # One accepted finding leaves the others failing the run, and a stale entry is pointed out.
    def test_partly_accepted_and_stale(self, lab_api, lab_accounts, tmp_path):
        search = _finding("rate-limit", Severity.MEDIUM, "GET /search")
        accepted = tmp_path / "accepted.json"
        accepted.write_text(json.dumps({"accepted": [
            {"fingerprint": search.fingerprint, "reason": "throttled at the gateway"},
            {"fingerprint": "0000000000000000", "reason": "fixed long ago"},
        ]}), encoding="utf-8")

        result = _lab_scan(lab_api, "--accepted", str(accepted), "--json")

        assert result.exit_code == 1
        report = json.loads(result.stdout)
        assert [f["endpoint"] for f in report["findings"] if f["accepted"]] == ["GET /search"]
        assert "1 accepted finding(s)" in _flat(result.stderr) and "0000000000000000" in result.stderr

    # On a partial scan (here: one check only) a missing finding proves nothing, so no stale note.
    def test_no_stale_note_on_a_filtered_scan(self, lab_api, lab_accounts, tmp_path):
        accepted = tmp_path / "accepted.json"
        accepted.write_text(json.dumps({"accepted": [{"fingerprint": "0000000000000000", "reason": "x"}]}), encoding="utf-8")

        result = _lab_scan(lab_api, "--only", "auth-required", "--accepted", str(accepted), "--json")

        assert "accepted finding(s)" not in _flat(result.stderr)


# ---------------------------------------------------------------------------------------------
# the spec download obeys the scan's rules


class TestSpecDownload:
    SPEC = json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}})

    # A host that isn't on the allowlist is refused before anything is sent.
    def test_allowlist_is_checked_first(self):
        transport = httpx.MockTransport(lambda r: pytest.fail("sent a request"))

        with httpx.Client(transport=transport) as client, pytest.raises(AllowlistError, match="not on the allowlist"):
            load_spec("http://other.test/openapi.json", client=client, allowlist=Allowlist(["api.test"]))

    def test_allowed_host_is_downloaded(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text=self.SPEC))

        with httpx.Client(transport=transport) as client:
            spec = load_spec("http://api.test/openapi.json", client=client, allowlist=Allowlist(["api.test"]))

        assert spec["info"]["title"] == "t"

    # A redirect is an error that says where it points, so the user can decide to use that URL.
    def test_redirect_names_its_target(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(302, headers={"Location": "http://elsewhere.test/spec"}))

        with httpx.Client(transport=transport) as client, pytest.raises(SpecError, match=r"redirects to http://elsewhere\.test/spec"):
            load_spec("http://api.test/openapi.json", client=client)

    # The lab serves its spec from /app/openapi.json in the container; in-process, point it at the repo's copy.
    @pytest.fixture
    def lab_serves_spec(self, clean_env):
        clean_env.setenv("SPEC_PATH", str(LAB_SPEC))

    # Scanning from the lab's own spec URL works: the host the user typed is the one allowed.
    def test_scan_from_a_spec_url(self, lab_serves_spec, lab_api, lab_accounts):
        result = runner.invoke(
            cli.app, ["scan", f"{lab_api}/openapi.json", "--i-have-authorization", "--only", "auth-required", "--json"]
        )

        assert result.exit_code == 1, result.output
        assert [f["endpoint"] for f in json.loads(result.stdout)["findings"]] == ["GET /users/{id}"]
