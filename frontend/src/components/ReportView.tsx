import { useRef, useState, type ReactNode } from "react";
import { checkName, severityLabel } from "../api/checks";
import type { Report } from "../api/types";
import { countBySeverity, dateTime, hostOf, plural, seconds, severitySummary } from "../lib/format";
import { FindingDetail } from "./FindingDetail";
import { FuzzText } from "./FuzzText";

function Meta({ report }: { report: Report }) {
  const items: [string, string][] = [
    ["Target", hostOf(report.target)],
    ["Started", dateTime(report.started_at)],
    ["Took", seconds(report.duration_s)],
    ["Requests sent", String(report.requests_sent)],
    ["Endpoints in the spec", String(report.endpoints_scanned)],
    ["Scanner", `apifuzz ${report.tool_version}`],
  ];
  return (
    <dl className="meta">
      {items.map(([term, value]) => (
        <div key={term}>
          <dt className="meta__term">{term}</dt>
          <dd className="meta__value">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Coverage({ report }: { report: Report }) {
  return (
    <section className="coverage" aria-labelledby="coverage-title">
      <h2 className="section-title" id="coverage-title">
        What was tested
      </h2>
      <p className="coverage__intro">
        An endpoint that wasn't tested isn't known to be safe. "Not applicable" means the check doesn't apply to that
        kind of endpoint, for example a rate limit on a delete.
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col" className="num">
                Tested
              </th>
              <th scope="col" className="num">
                Not tested
              </th>
              <th scope="col" className="num">
                Not applicable
              </th>
            </tr>
          </thead>
          <tbody>
            {report.coverage.map((c) => (
              <tr key={c.check}>
                <th scope="row">
                  {checkName(c.check)}
                  {c.notes.map((n) => (
                    <span className="table__note" key={n}>
                      {n}
                    </span>
                  ))}
                </th>
                <td className="num">{c.tested}</td>
                <td className={`num${c.not_tested ? " table__warn" : ""}`}>{c.not_tested}</td>
                <td className="num">{c.not_applicable}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function ReportView({ report, banner }: { report: Report; banner?: ReactNode }) {
  const findings = report.findings;
  const [selected, setSelected] = useState(0);
  const detailRef = useRef<HTMLDivElement>(null);
  const current = findings[selected];

  // On a narrow screen the detail sits below the list, so move to it when a finding is picked.
  // Done here, on the click, rather than in an effect, so it never fires on first render.
  function select(i: number) {
    setSelected(i);
    if (window.matchMedia("(max-width: 900px)").matches) {
      requestAnimationFrame(() => detailRef.current?.scrollIntoView({ block: "start" }));
    }
  }

  const headline =
    findings.length === 0
      ? `No findings across ${plural(report.endpoints_scanned, "endpoint")}`
      : `${plural(findings.length, "finding")} across ${plural(report.endpoints_scanned, "endpoint")}`;

  return (
    <>
      <header className="report-head">
        {banner}
        <div>
          <h1 className="page-title">
            <FuzzText text={headline} />
          </h1>
          {findings.length > 0 && <p className="lede">{severitySummary(findings)}.</p>}
        </div>
        {(report.incomplete || report.errors.length > 0) && (
          <div className="notice notice--error" role="status">
            <strong>This scan didn't finish cleanly.</strong>{" "}
            {report.errors.length > 0 ? report.errors.join(" ") : "Some requests got no answer."} Missing findings
            may only mean those parts weren't reached.
          </div>
        )}
        <Meta report={report} />
        {findings.length > 0 && (
          <div className="strip">
            <div className="strip__bar" role="group" aria-label="Findings, worst first">
              {findings.map((f, i) => (
                <button
                  key={f.fingerprint}
                  type="button"
                  className={`strip__seg strip__seg--${f.severity}`}
                  aria-current={i === selected}
                  aria-label={`${severityLabel(f.severity)}: ${f.endpoint}`}
                  title={`${severityLabel(f.severity)}: ${f.endpoint}`}
                  onClick={() => select(i)}
                />
              ))}
            </div>
            <div className="strip__legend">
              {countBySeverity(findings).map(([s, n]) => (
                <span key={s} className={`sev sev--${s}`}>
                  {n} {severityLabel(s).toLowerCase()}
                </span>
              ))}
            </div>
          </div>
        )}
      </header>

      {findings.length === 0 ? (
        <div className="empty">
          <p className="empty__title">Every check that ran came back clean.</p>
          <p className="empty__text">
            Look at What was tested below before you call this API safe: a check that couldn't test an endpoint says
            so there.
          </p>
        </div>
      ) : (
        <div className="report-body">
          <nav aria-label="Findings">
            <ul className="findings">
              {findings.map((f, i) => (
                <li key={f.fingerprint}>
                  <button
                    type="button"
                    className="findings__item"
                    aria-current={i === selected}
                    onClick={() => select(i)}
                  >
                    <span className={`sev sev--${f.severity}`}>{severityLabel(f.severity)}</span>
                    <span className="findings__endpoint">{f.endpoint}</span>
                    <span className="findings__title">{f.title}</span>
                    {f.accepted && <span className="findings__accepted">Accepted</span>}
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          <div ref={detailRef}>{current && <FindingDetail key={current.fingerprint} finding={current} />}</div>
        </div>
      )}

      <Coverage report={report} />
    </>
  );
}
