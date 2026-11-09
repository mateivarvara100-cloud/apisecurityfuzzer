"""Turn a ScanResult into something to show or save, with secrets removed.

The HTTP client records requests exactly as sent, tokens included. Every output path goes through
`redacted()` first (unless the user explicitly passes --no-redact), so a report can be shared
without leaking the test accounts' credentials.
"""

import html  # escape text before putting it in the HTML report
from datetime import datetime, timezone

from rich.table import Table
from rich.text import Text

from apifuzz.finding import Severity
from apifuzz.http_client import Exchange
from apifuzz.scanner import ScanResult

# Header names (lower case) whose values are replaced. Covers both directions of a session.
_SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
REDACTED = "[redacted]"

# Colour for each severity in the table.
_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def redacted(result: ScanResult) -> ScanResult:
    """A deep copy of `result` with secret header values replaced by "[redacted]"."""
    copy = result.model_copy(deep=True)  # never modify the caller's data
    for finding in copy.findings:
        for exchange in finding.evidence:
            for headers in (exchange.request.headers, exchange.response.headers):
                for name in headers:
                    if name.lower() in _SECRET_HEADERS:
                        headers[name] = REDACTED
    return copy


def to_json(result: ScanResult, redact: bool = True) -> str:
    # mode="json" turns enums and other special types into plain JSON values.
    return (redacted(result) if redact else result).model_dump_json(indent=2)


def headline(result: ScanResult) -> str:
    """One line summing up a scan, e.g. "6 endpoints scanned · 3 findings (1 critical, 2 medium)"."""
    e, n = result.endpoints_scanned, len(result.findings)
    text = f"{e} endpoint{'' if e == 1 else 's'} scanned · {n} finding{'' if n == 1 else 's'}"
    counts = [(sev, sum(f.severity is sev for f in result.findings)) for sev in sorted(Severity, reverse=True)]
    parts = [f"{c} {sev.name.lower()}" for sev, c in counts if c]
    return f"{text} ({', '.join(parts)})" if parts else text


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
    for f in result.findings:
        table.add_row(
            Text(str(f.severity), style=_STYLE[f.severity]),
            Text(f"{f.check}\n{f.owasp.split(' ', 1)[0]}" if f.owasp else f.check),  # e.g. "bola" + "API1:2023"
            Text(f.endpoint),  # Text(): show "[...]" in a path literally
            Text(f"{f.title}\n{f.detail}" + (f"\nFix: {f.remediation}" if f.remediation else "")),
        )
    return table


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


def to_html(result: ScanResult, title: str = "apifuzz report", redact: bool = True) -> str:
    """A standalone HTML report: findings grouped by severity, each expandable to its evidence."""
    shown = redacted(result) if redact else result
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
    ]
    if not shown.findings:
        out.append("<p>No findings.</p>")
    for sev in sorted(Severity, reverse=True):
        group = [f for f in shown.findings if f.severity is sev]
        if not group:
            continue
        out.append(f"<h2 class='{sev.name}'>{sev.name.title()} ({len(group)})</h2>")
        for f in group:
            out.append(
                f"<details><summary><span class='sev {sev.name}'>{sev.name}</span>"
                f"<code>{e(f.endpoint)}</code><span>{e(f.title)}</span>"
                f"<span class='muted'>{e(f.check)}</span></summary><div class='body'>"
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
    if shown.errors:
        out.append("<h2>Warnings</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in shown.errors) + "</ul>")
    out.append("</main></body></html>")
    return "\n".join(out)
