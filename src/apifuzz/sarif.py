"""Write a ScanResult as SARIF 2.1.0, the format GitHub code scanning (and other tools) read.

SARIF was designed for static analysis, where every result points at a line of source code. A
scan of a running API has no source line, so each finding points at the place in the OpenAPI spec
that declares the endpoint: the operation's line when the spec is a local file, line 1 otherwise.
On GitHub that puts the finding next to the route's definition in a pull request.

How a finding maps to SARIF:
  check id            -> a rule (one per check that ran), with the check's description
  severity            -> `level` (error / warning / note) and the rule's `security-severity`,
                         which is what GitHub uses to label a result critical / high / medium / low
  fingerprint         -> `partialFingerprints`, so the same finding is recognised from run to run
  accepted finding    -> a `suppressions` entry carrying the reason, so it shows as dismissed

Evidence (requests and responses) is deliberately left out: a SARIF file is uploaded to a
service, and the HTML and JSON reports are the place for evidence. Test tokens are still replaced
in every message, in case a check quoted one.
"""

import json
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from apifuzz.checks import all_checks
from apifuzz.finding import Finding, Severity
from apifuzz.scanner import ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_HOMEPAGE = "https://github.com/mateivarvara100-cloud/apisecurityfuzzer"
_MIN_SECRET = 6  # same floor as report.py: shorter "secrets" would garble ordinary text

# SARIF has three levels; GitHub's finer scale comes from `security-severity` (a CVSS-like score).
_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
# GitHub's bands: 9.0+ critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SCORE = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "1.0",
}


def _spec_location(spec_source: str) -> tuple[str, list[str]]:
    """The spec's path as SARIF should name it, and its lines (empty when it can't be read).

    A local file is named relative to the current directory with forward slashes, which is how
    a repository-relative path looks when the scan runs from the repository root. A spec given as
    a URL is named by the last part of its path, and has no lines to search.
    """
    if spec_source.lower().startswith(("http://", "https://")):
        name = urlsplit(spec_source).path.rsplit("/", 1)[-1]
        return name or "openapi.json", []
    path = Path(spec_source)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        lines = []
    try:
        shown = path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:  # the spec is outside the current directory: its name is the best we have
        shown = Path(path.name)
    return shown.as_posix(), lines


def _key_line(text: str, key: str) -> bool:
    """True if this line of JSON or YAML declares `key`, e.g. `"/orders/{id}": {` or `get:`."""
    stripped = text.strip()
    return any(stripped.startswith(start) for start in (f'"{key}"', f"'{key}'", f"{key}:"))


def _operation_line(lines: list[str], endpoint: str) -> int:
    """The 1-based line where the spec declares `endpoint` ("GET /orders/{id}"), or 1 if not found.

    Finds the line with the path, then the method under it. If only the path is found, its line
    is used. This is a text search, not a parser: good enough to land on the right place, and it
    never fails the report.
    """
    method, _, path = endpoint.partition(" ")
    for index, text in enumerate(lines):
        if not _key_line(text, path):
            continue
        for offset, later in enumerate(lines[index + 1:], 1):
            if _key_line(later, method.lower()):
                return index + 1 + offset
            if re.match(r"""\s*["']?/""", later):  # the next path begins: this one has no such method
                break
        return index + 1
    return 1


def _rule_name(check_id: str) -> str:
    return "".join(part.capitalize() for part in check_id.split("-"))  # "auth-required" -> "AuthRequired"


def _rules(result: ScanResult) -> list[dict]:
    known = {cls.id: cls for cls in all_checks()}
    ids = list(result.checks_run) + [f.check for f in result.findings if f.check not in result.checks_run]
    rules = []
    for check_id in dict.fromkeys(ids):  # in order, without repeats
        cls = known.get(check_id)
        description = cls.description if cls else check_id
        owasp = cls.owasp if cls else ""
        found = [f for f in result.findings if f.check == check_id]
        properties: dict[str, object] = {"tags": ["security", *([owasp.split(" ", 1)[0]] if owasp else [])]}
        if found:
            # One score per rule: the worst severity this check reported in this run.
            properties["security-severity"] = _SCORE[max(f.severity for f in found)]
        fix = next((f.remediation for f in found if f.remediation), "")
        rules.append({
            "id": check_id,
            "name": _rule_name(check_id),
            "shortDescription": {"text": description},
            "fullDescription": {"text": f"{description} ({owasp})" if owasp else description},
            "help": {"text": fix or description},
            "helpUri": f"{_HOMEPAGE}#how-each-check-works",
            "properties": properties,
        })
    return rules


def _result(finding: Finding, rule_index: int, uri: str, line: int, scrub) -> dict:
    entry: dict[str, object] = {
        "ruleId": finding.check,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": scrub(f"{finding.endpoint}: {finding.title}. {finding.detail}")},
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}},
            "logicalLocations": [{"fullyQualifiedName": finding.endpoint, "kind": "resource"}],
        }],
        "partialFingerprints": {"apifuzzFingerprint/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.name,
            "owasp": finding.owasp,
            "endpoint": finding.endpoint,
            "key": finding.key,
        },
    }
    if finding.accepted:
        entry["suppressions"] = [{"kind": "external", "justification": scrub(finding.accepted_reason)}]
    return entry


def to_sarif(result: ScanResult, spec_source: str, secrets: Iterable[str | None] = ()) -> str:
    """The scan as a SARIF 2.1.0 document (a JSON string)."""
    known = [s for s in secrets if s and len(s) >= _MIN_SECRET]

    def scrub(text: str) -> str:
        for secret in known:
            text = text.replace(secret, "[redacted]")
        return text

    uri, lines = _spec_location(spec_source)
    rules = _rules(result)
    index_of = {rule["id"]: i for i, rule in enumerate(rules)}
    run = {
        "tool": {"driver": {
            "name": "apifuzz",
            "version": result.tool_version,
            "informationUri": _HOMEPAGE,
            "rules": rules,
        }},
        "invocations": [{
            # False when the scan stopped early: a reader must not take a partial run for a clean one.
            "executionSuccessful": not result.incomplete,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": scrub(line)}} for line in result.errors
            ],
        }],
        "results": [
            _result(f, index_of[f.check], uri, _operation_line(lines, f.endpoint), scrub) for f in result.findings
        ],
        "properties": {
            "target": result.target,
            "requestsSent": result.requests_sent,
            "coverage": [c.model_dump() for c in result.coverage],
        },
    }
    return json.dumps({"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}, indent=2)
