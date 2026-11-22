// Two scans of the same target, side by side: what is new, what was fixed, what is still open.
//
// Findings are matched by fingerprint (a hash of check, endpoint and key: the same in every run,
// and what the CLI's accepted-findings file uses too). A finding missing from the later scan only
// counts as fixed if the later scan could have found it again: the check ran, the scan finished,
// and the check didn't say that endpoint went untested. Otherwise it is "not re-tested", because
// an absent finding is only good news if something looked.

import type { Finding, Report } from "../api/types";

export interface Comparison {
  fresh: Finding[]; // in the later scan only
  fixed: Finding[]; // in the earlier scan only, and the later one looked again
  open: Finding[]; // in both (shown as the later scan has it)
  unchecked: Finding[]; // in the earlier scan only, but the later one couldn't tell
}

/** Did `report` run the finding's check on its endpoint to a verdict? */
function retested(f: Finding, report: Report): boolean {
  if (report.incomplete || !report.checks_run.includes(f.check)) return false;
  const coverage = report.coverage.find((c) => c.check === f.check);
  if (!coverage) return false;
  // Each untested endpoint is noted as "GET /orders/{id}: <reason>" (or just the endpoint).
  return !coverage.notes.some((n) => n === f.endpoint || n.startsWith(`${f.endpoint}:`));
}

export function compare(earlier: Report, later: Report): Comparison {
  const before = new Set(earlier.findings.map((f) => f.fingerprint));
  const after = new Set(later.findings.map((f) => f.fingerprint));
  const gone = earlier.findings.filter((f) => !after.has(f.fingerprint));
  return {
    fresh: later.findings.filter((f) => !before.has(f.fingerprint)),
    open: later.findings.filter((f) => before.has(f.fingerprint)),
    fixed: gone.filter((f) => retested(f, later)),
    unchecked: gone.filter((f) => !retested(f, later)),
  };
}
