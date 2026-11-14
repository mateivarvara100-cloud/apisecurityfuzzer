"""The file of accepted findings: known findings a team has decided to live with, for now.

Without it, a CI job that fails on findings can only be all-or-nothing: the first finding nobody
can fix this week turns the job red for good, and people stop looking at it. With it, a finding
can be accepted with a written reason. It is still shown in every report, marked as accepted,
but it no longer counts towards --fail-on, so the job goes red only for something new.

The file is JSON, meant to be committed next to the spec and reviewed like code:

    {
      "accepted": [
        {
          "fingerprint": "3f2a9c0d1b7e4a55",
          "check": "rate-limit",
          "endpoint": "GET /search",
          "reason": "Throttled at the gateway, which the scan does not go through."
        }
      ]
    }

Only `fingerprint` and `reason` are read. `check` and `endpoint` are there for the person reading
the file. A reason is required: accepting a finding is a decision, and the file should say why.
"""

import json
from pathlib import Path

from apifuzz.errors import ApifuzzError
from apifuzz.finding import Finding


class AcceptedFileError(ApifuzzError):
    """The file of accepted findings is missing, unreadable, or has an entry without a reason."""


def load_accepted(path: Path) -> dict[str, str]:
    """Read the file and return {fingerprint: reason}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AcceptedFileError(f"could not read the accepted-findings file {path}: {exc}") from exc
    except ValueError as exc:
        raise AcceptedFileError(f"the accepted-findings file {path} is not valid JSON: {exc}") from exc
    entries = data.get("accepted") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise AcceptedFileError(f'the accepted-findings file {path} must be an object with an "accepted" list')

    accepted: dict[str, str] = {}
    for number, entry in enumerate(entries, 1):
        fingerprint = entry.get("fingerprint") if isinstance(entry, dict) else None
        reason = entry.get("reason") if isinstance(entry, dict) else None
        if not isinstance(fingerprint, str) or not fingerprint:
            raise AcceptedFileError(f"{path}: entry {number} has no fingerprint")
        if not isinstance(reason, str) or not reason.strip():
            label = f"{entry.get('check', '?')} on {entry.get('endpoint', '?')}"
            raise AcceptedFileError(
                f"{path}: entry {number} ({label}) has no reason. Say why the finding is accepted, or remove the entry."
            )
        accepted[fingerprint] = reason.strip()
    return accepted


def apply_accepted(findings: list[Finding], accepted: dict[str, str]) -> list[str]:
    """Mark the findings whose fingerprint is accepted. Returns the fingerprints that matched nothing.

    An entry that matches nothing is stale: the finding was fixed, or the endpoint changed. The
    caller warns about those, so the file doesn't quietly fill up with dead entries.
    """
    seen = set()
    for finding in findings:
        reason = accepted.get(finding.fingerprint)
        if reason is not None:
            finding.accepted = True
            finding.accepted_reason = reason
            seen.add(finding.fingerprint)
    return [fingerprint for fingerprint in accepted if fingerprint not in seen]


def write_accepted(path: Path, findings: list[Finding]) -> None:
    """Write a starting file listing every current finding, each with an empty reason to fill in.

    Findings that are already accepted keep their reason. The file will not load until every
    reason is filled in, so nothing is accepted without someone writing down why.
    """
    entries = [
        {"fingerprint": f.fingerprint, "check": f.check, "endpoint": f.endpoint, "title": f.title,
         "reason": f.accepted_reason}
        for f in findings
    ]
    path.write_text(json.dumps({"accepted": entries}, indent=2) + "\n", encoding="utf-8")
