"""Run a set of checks against a set of endpoints and collect what they report.

A failure talking to one endpoint (connection refused, timeout) is recorded and the scan moves
on, so one broken route doesn't hide results from the rest. A refused host (AllowlistError) is
different: it means the scan is misconfigured, so it stops everything.
"""

from pydantic import BaseModel

from apifuzz.checks.base import Check, ScanContext
from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import RequestError
from apifuzz.finding import Finding


class ScanResult(BaseModel):
    findings: list[Finding] = []  # worst first
    errors: list[str] = []  # one line per (check, endpoint) that couldn't be completed
    checks_run: list[str] = []  # the ids of the checks that ran
    endpoints_scanned: int = 0


def run_scan(endpoints: list[Endpoint], checks: list[type[Check]], ctx: ScanContext) -> ScanResult:
    result = ScanResult(checks_run=[c.id for c in checks], endpoints_scanned=len(endpoints))
    if not ctx.endpoints:
        ctx.endpoints = endpoints  # let checks see the whole scan (e.g. bola's id recon)
    for check_cls in checks:
        check = check_cls()
        for endpoint in endpoints:
            try:
                result.findings.extend(check.run(endpoint, ctx))
            except RequestError as exc:
                # A network-level failure on this one request: note it and carry on.
                result.errors.append(f"{check.id} on {endpoint.method} {endpoint.path}: {exc}")
            # AllowlistError is deliberately NOT caught: it propagates and aborts the scan.
    # Stable sort: worst severity first, ties keep the order the checks produced them in.
    result.findings.sort(key=lambda f: f.severity, reverse=True)
    return result
