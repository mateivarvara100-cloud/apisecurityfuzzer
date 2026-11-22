"""Run a set of checks against a set of endpoints and collect what they report.

A failure talking to one endpoint (connection refused, timeout) is recorded and the scan moves
on, so one broken route doesn't hide results from the rest. A refused host (AllowlistError) is
different: it means the scan is misconfigured, so it stops everything.

Besides findings, the result says what was actually tested. For every check it counts the
endpoints that were tested, the ones that could not be (with the reason), and the ones the check
does not apply to. A report with no findings is only good news if something was tested.
"""

import time
from collections.abc import Callable
from datetime import datetime, timezone

from pydantic import BaseModel

from apifuzz import __version__
from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext
from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import RequestError, RequestLimitError
from apifuzz.finding import Finding

SCHEMA_VERSION = 2  # bump when the JSON report's shape changes in a way that breaks readers


class Coverage(BaseModel):
    """What one check did across the scan."""

    check: str
    tested: int = 0  # endpoints where the check reached a verdict
    not_tested: int = 0  # endpoints the check applies to but could not judge
    not_applicable: int = 0  # endpoints the check has nothing to look for on
    notes: list[str] = []  # one line per not-tested endpoint: "GET /orders/{id}: <reason>"


class ScanResult(BaseModel):
    schema_version: int = SCHEMA_VERSION
    tool_version: str = __version__
    target: str = ""  # the base URL that was scanned
    started_at: str = ""  # UTC, ISO 8601
    duration_s: float = 0.0
    requests_sent: int = 0
    findings: list[Finding] = []  # worst first
    errors: list[str] = []  # one line per (check, endpoint) that couldn't be completed
    checks_run: list[str] = []  # the ids of the checks that ran
    endpoints_scanned: int = 0
    coverage: list[Coverage] = []  # one entry per check, in the order they ran
    incomplete: bool = False  # True when the scan stopped early (request limit reached)


# Called before each (check, endpoint) step with the check's id, the step's number (from 0) and
# the number of steps in the whole scan.
StepHook = Callable[[str, int, int], None]


def run_scan(
    endpoints: list[Endpoint],
    checks: list[type[Check]],
    ctx: ScanContext,
    *,
    on_step: StepHook | None = None,
    should_stop: Callable[[], str | None] | None = None,
) -> ScanResult:
    """Run every check on every endpoint.

    `on_step` reports progress. `should_stop` is asked before each step; when it returns a reason,
    the scan ends there, between two steps, so no check is cut off halfway (a check that created
    test data has deleted it again). What was found so far is kept and the result is marked
    incomplete, as when the request limit is reached.
    """
    started = time.perf_counter()
    result = ScanResult(
        checks_run=[c.id for c in checks],
        endpoints_scanned=len(endpoints),
        target=ctx.settings.base_url,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    if not ctx.endpoints:
        ctx.endpoints = endpoints  # let checks see the whole scan (e.g. bola's id recon)
    total = len(checks) * len(endpoints)
    step = 0
    try:
        for check_cls in checks:
            check = check_cls()
            coverage = Coverage(check=check.id)
            result.coverage.append(coverage)
            for endpoint in endpoints:
                reason = should_stop() if should_stop else None
                if reason:
                    result.errors.append(f"scan stopped early: {reason}")
                    result.incomplete = True
                    raise _Stopped
                if on_step:
                    on_step(check.id, step, total)
                step += 1
                label = f"{endpoint.method} {endpoint.path}"
                try:
                    result.findings.extend(check.run(endpoint, ctx))
                except RequestError as exc:
                    # A network-level failure on this one request: note it and carry on.
                    result.errors.append(f"{check.id} on {label}: {exc}")
                    ctx.outcomes[(check.id, label)] = (NOT_TESTED, "a request failed (see warnings)")
                # AllowlistError is deliberately NOT caught: it propagates and aborts the scan.
                _count(coverage, label, ctx.outcomes.get((check.id, label)))
    except RequestLimitError as exc:
        # The request budget ran out. Keep what was found so far, but say the scan is partial.
        result.errors.append(f"scan stopped early: {exc}")
        result.incomplete = True
    except _Stopped:
        pass  # asked to stop (should_stop); already noted above
    # Anything a check created on the target and could not remove again is said out loud.
    result.errors.extend(f"left behind on the target: {line}" for line in ctx.leftovers)
    # Stable sort: worst severity first, ties keep the order the checks produced them in.
    result.findings.sort(key=lambda f: f.severity, reverse=True)
    result.requests_sent = ctx.client.requests_sent
    result.duration_s = round(time.perf_counter() - started, 2)
    return result


class _Stopped(Exception):
    """Internal: leaves both loops at once when should_stop asks the scan to end."""


def _count(coverage: Coverage, label: str, outcome: tuple[str, str] | None) -> None:
    status, reason = outcome or ("", "")
    if status == TESTED:
        coverage.tested += 1
    elif status == NOT_TESTED:
        coverage.not_tested += 1
        coverage.notes.append(f"{label}: {reason}" if reason else label)
    else:
        coverage.not_applicable += 1
