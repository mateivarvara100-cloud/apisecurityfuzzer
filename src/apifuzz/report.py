"""Turn a ScanResult into something to show or save, with secrets removed.

The HTTP client records requests exactly as sent, tokens included, and a finding's evidence can
hold another user's data (that is what a BOLA finding is). Every output path goes through
`redacted()` first (unless the user explicitly passes --no-redact), so a report can be shared:
credentials are replaced, personal fields in bodies are masked, and bodies are cut to an excerpt.
"""

import html  # escape text before putting it in the HTML report
import json  # read a body to mask its sensitive fields
import re  # find e-mail addresses in body text
from collections.abc import Iterable
from datetime import datetime, timezone

from rich.table import Table
from rich.text import Text

from apifuzz.finding import Severity
from apifuzz.http_client import Exchange
from apifuzz.scanner import ScanResult

# Header names (lower case) whose values are replaced. Covers both directions of a session.
_SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
REDACTED = "[redacted]"
# A JSON field whose name contains one of these has its value replaced in a redacted report.
_SENSITIVE_KEY_PARTS = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "authorization",
    "email", "phone", "ssn", "iban", "card",
)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_BODY_EXCERPT = 600  # characters of a body kept in a redacted report: enough to see its shape
_MIN_SECRET = 6  # shorter "secrets" are not searched for: replacing "1" or "bob" everywhere garbles the report

# Colour for each severity in the table.
_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _mask(value: object) -> object:
    # Walk a parsed JSON value and replace the value of every sensitive-looking key.
    if isinstance(value, dict):
        return {
            k: REDACTED if any(part in k.lower() for part in _SENSITIVE_KEY_PARTS) else _mask(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mask(item) for item in value]
    return value


def _scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def _clean_body(body: str | None, secrets: list[str]) -> str | None:
    """A body made safe to share: sensitive fields and e-mail addresses masked, then cut short."""
    if not body:
        return body
    try:
        parsed = json.loads(body)
    except ValueError:
        text = body  # not JSON (or cut off mid-way): fall back to the text rules below
    else:
        text = json.dumps(_mask(parsed)) if isinstance(parsed, (dict, list)) else body
    text = _EMAIL.sub(REDACTED, _scrub(text, secrets))
    if len(text) > _BODY_EXCERPT:
        text = text[:_BODY_EXCERPT] + " ... [shortened]"
    return text


def redacted(result: ScanResult, secrets: Iterable[str | None] = ()) -> ScanResult:
    """A deep copy of `result` that is safe to share.

    Secret header values become "[redacted]". The values in `secrets` (the test accounts' tokens)
    are replaced wherever they appear: any header, URL, body or warning. Bodies also have their
    sensitive fields masked and are shortened to an excerpt.
    """
    known = [s for s in secrets if s and len(s) >= _MIN_SECRET]
    copy = result.model_copy(deep=True)  # never modify the caller's data
    copy.errors = [_scrub(line, known) for line in copy.errors]
    for finding in copy.findings:
        for exchange in finding.evidence:
            exchange.request.url = _scrub(exchange.request.url, known)
            exchange.request.body = _clean_body(exchange.request.body, known)
            exchange.response.body = _clean_body(exchange.response.body, known) or ""
            for headers in (exchange.request.headers, exchange.response.headers):
                for name in headers:
                    if name.lower() in _SECRET_HEADERS:
                        headers[name] = REDACTED
                    else:
                        headers[name] = _scrub(headers[name], known)
    return copy


def to_json(result: ScanResult, redact: bool = True, secrets: Iterable[str | None] = ()) -> str:
    # mode="json" turns enums and other special types into plain JSON values.
    return (redacted(result, secrets) if redact else result).model_dump_json(indent=2)


def headline(result: ScanResult) -> str:
    """One line summing up a scan, e.g. "6 endpoints scanned · 3 findings (1 critical, 2 medium)"."""
    # Accepted findings (see accepted.py) are counted apart: the headline is about what is open.
    open_findings = [f for f in result.findings if not f.accepted]
    accepted = len(result.findings) - len(open_findings)
    e, n = result.endpoints_scanned, len(open_findings)
    text = f"{e} endpoint{'' if e == 1 else 's'} scanned · {n} finding{'' if n == 1 else 's'}"
    counts = [(sev, sum(f.severity is sev for f in open_findings)) for sev in sorted(Severity, reverse=True)]
    parts = [f"{c} {sev.name.lower()}" for sev, c in counts if c]
    if parts:
        text = f"{text} ({', '.join(parts)})"
    return f"{text} · {accepted} accepted" if accepted else text


def findings_table(result: ScanResult) -> Table:
    checks = len(result.checks_run)
    table = Table(
        title="Scan findings",
        caption=f"{headline(result)} · {checks} check{'' if checks == 1 else 's'} run",
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Endpoint")
    table.add_column("Finding")
    # Open findings first (already worst first), then the accepted ones, dimmed and without detail.
    for f in sorted(result.findings, key=lambda f: f.accepted):
        check = Text(f"{f.check}\n{f.owasp.split(' ', 1)[0]}" if f.owasp else f.check)  # e.g. "bola" + "API1:2023"
        if f.accepted:
            table.add_row(
                Text(f"{f.severity}\naccepted", style="dim"), check, Text(f.endpoint),
                Text(f"{f.title}\nAccepted: {f.accepted_reason}", style="dim"),
            )
            continue
        table.add_row(
            Text(str(f.severity), style=_STYLE[f.severity]),
            check,
            Text(f.endpoint),  # Text(): show "[...]" in a path literally
            Text(f"{f.title}\n{f.detail}" + (f"\nFix: {f.remediation}" if f.remediation else "")),
        )
    return table


def coverage_table(result: ScanResult) -> Table:
    """What each check actually tested. "0 findings" means little if "Tested" is 0 too."""
    table = Table(
        title="What was tested",
        caption=f"{result.requests_sent} request{'' if result.requests_sent == 1 else 's'} sent to {result.target}",
    )
    table.add_column("Check", no_wrap=True)
    table.add_column("Tested", justify="right")
    table.add_column("Not tested", justify="right")
    table.add_column("Not applicable", justify="right")
    for c in result.coverage:
        table.add_row(c.check, str(c.tested), Text(str(c.not_tested), style="yellow" if c.not_tested else ""),
                      str(c.not_applicable))
    return table


def coverage_notes(result: ScanResult) -> list[str]:
    """One line per endpoint a check applies to but could not judge: "bola: GET /x: reason"."""
    return [f"{c.check}: {note}" for c in result.coverage for note in c.notes]


# ---------------------------------------------------------------------------------------------
# HTML: one self-contained file (inline CSS, no scripts, no external links), safe to attach.

_CSS = """
:root { color-scheme: light dark; --bg:#fff; --fg:#1b1b1f; --muted:#5d5d66; --line:#d9d9e0; --card:#f6f6f9;
  --critical:#a4161a; --high:#c0392b; --medium:#9a6700; --low:#2b6cb0; --info:#6b7280; }
@media (prefers-color-scheme: dark) { :root { --bg:#141418; --fg:#ececf1; --muted:#a0a0ab; --line:#33333b;
  --card:#1d1d23; --critical:#ff6b6b; --high:#ff8fa3; --medium:#f6c35b; --low:#7fb3ff; --info:#9ca3af; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.1rem; margin: 28px 0 8px; }
.muted { color: var(--muted); }
.headline { font-size: 1.05rem; margin: 12px 0 4px; }
details { background: var(--card); border: 1px solid var(--line); border-radius: 8px; margin: 8px 0; }
summary { cursor: pointer; padding: 10px 14px; }
summary > * { margin-right: 10px; }
.body { padding: 0 14px 14px; }
.sev { font-weight: 700; font-size: .78rem; letter-spacing: .04em; }
.CRITICAL { color: var(--critical); } .HIGH { color: var(--high); } .MEDIUM { color: var(--medium); }
.LOW { color: var(--low); } .INFO { color: var(--info); }
code, pre { font: 13px/1.45 ui-monospace, "Cascadia Code", Consolas, monospace; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 10px;
  overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin: 6px 0 12px; }
ul { padding-left: 20px; }
table { border-collapse: collapse; margin: 8px 0; }
th, td { border: 1px solid var(--line); padding: 4px 12px; text-align: right; }
th:first-child, td:first-child { text-align: left; }
"""


def _exchange_text(ex: Exchange) -> tuple[str, str]:
    req = ex.request
    req_lines = [f"{req.method} {req.url}"] + [f"{k}: {v}" for k, v in req.headers.items()]
    if req.body:
        req_lines += ["", req.body]
    res = ex.response
    res_lines = [f"HTTP {res.status_code}  ({ex.elapsed_ms:.0f} ms)"] + [f"{k}: {v}" for k, v in res.headers.items()]
    if res.body:
        res_lines += ["", res.body + (" [truncated]" if res.truncated else "")]
    return "\n".join(req_lines), "\n".join(res_lines)


def to_html(
    result: ScanResult, title: str = "apifuzz report", redact: bool = True, secrets: Iterable[str | None] = ()
) -> str:
    """A standalone HTML report: findings grouped by severity, each expandable to its evidence."""
    shown = redacted(result, secrets) if redact else result
    e = html.escape
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{e(title)}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{e(title)}</h1>",
        f"<p class='muted'>Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC · checks: "
        f"{e(', '.join(shown.checks_run) or 'none')}"
        f"{'' if redact else ' · <strong>secrets NOT redacted</strong>'}</p>",
        f"<p class='headline'><strong>{e(headline(shown))}</strong></p>",
        f"<p class='muted'>Target {e(shown.target or 'unknown')} · {shown.requests_sent} requests sent · "
        f"{shown.duration_s:g} s · apifuzz {e(shown.tool_version)}</p>",
    ]
    if shown.incomplete:
        out.append("<p><strong>This scan stopped early, so the results are partial.</strong> See the warnings.</p>")
    if not shown.findings:
        out.append("<p>No findings.</p>")
    # One group per severity for the open findings, then one group for the accepted ones.
    groups = [
        (sev.name, sev.name.title(), [f for f in shown.findings if f.severity is sev and not f.accepted])
        for sev in sorted(Severity, reverse=True)
    ]
    groups.append(("muted", "Accepted", [f for f in shown.findings if f.accepted]))
    for css, label, group in groups:
        if not group:
            continue
        out.append(f"<h2 class='{css}'>{label} ({len(group)})</h2>")
        for f in group:
            sev = f.severity
            out.append(
                f"<details><summary><span class='sev {sev.name}'>{sev.name}</span>"
                f"<code>{e(f.endpoint)}</code><span>{e(f.title)}</span>"
                f"<span class='muted'>{e(f.check)}</span></summary><div class='body'>"
                + (f"<p><strong>Accepted:</strong> {e(f.accepted_reason)}</p>" if f.accepted else "")
                + (f"<p class='muted'>OWASP {e(f.owasp)}</p>" if f.owasp else "")
                + f"<p>{e(f.detail)}</p>"
            )
            if f.remediation:
                out.append(f"<p><strong>Fix:</strong> {e(f.remediation)}</p>")
            for i, ex in enumerate(f.evidence, 1):
                req, res = _exchange_text(ex)
                out.append(f"<p class='muted'>Evidence {i}: request</p><pre>{e(req)}</pre>")
                out.append(f"<p class='muted'>Evidence {i}: response</p><pre>{e(res)}</pre>")
            out.append("</div></details>")
    if shown.coverage:
        out.append(
            "<h2>What was tested</h2><p class='muted'>No findings is only good news for endpoints "
            "that were tested.</p><table><tr><th>Check</th><th>Tested</th><th>Not tested</th>"
            "<th>Not applicable</th></tr>"
            + "".join(
                f"<tr><td>{e(c.check)}</td><td>{c.tested}</td><td>{c.not_tested}</td><td>{c.not_applicable}</td></tr>"
                for c in shown.coverage
            )
            + "</table>"
        )
        notes = coverage_notes(shown)
        if notes:
            out.append("<p>Not tested:</p><ul>" + "".join(f"<li>{e(n)}</li>" for n in notes) + "</ul>")
    if shown.errors:
        out.append("<h2>Warnings</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in shown.errors) + "</ul>")
    out.append("</main></body></html>")
    return "\n".join(out)
