import { checkName, severityLabel } from "../api/checks";
import type { Finding } from "../api/types";
import { Evidence } from "./Evidence";

export function FindingDetail({ finding }: { finding: Finding }) {
  const [method, ...rest] = finding.endpoint.split(" ");
  return (
    <article className="detail" aria-labelledby="finding-title">
      <p className="detail__endpoint">
        <span className="detail__method">{method}</span>
        {rest.join(" ")}
      </p>
      <h2 className="detail__title" id="finding-title">
        {finding.title}
      </h2>
      <div className="detail__tags">
        <span className={`sev sev--${finding.severity}`}>{severityLabel(finding.severity)}</span>
        <span>{checkName(finding.check)}</span>
        <span>{finding.owasp}</span>
        <span>
          Fingerprint <code>{finding.fingerprint}</code>
        </span>
      </div>
      {finding.accepted && (
        <p className="accepted-note">
          Accepted, so it doesn't fail the scan: {finding.accepted_reason || "no reason given"}
        </p>
      )}
      <p className="detail__text">{finding.detail}</p>

      <h3 className="detail__heading">What was sent</h3>
      <Evidence finding={finding} />

      {finding.remediation && (
        <>
          <h3 className="detail__heading">How to fix it</h3>
          <p className="fix">{finding.remediation}</p>
        </>
      )}
    </article>
  );
}
