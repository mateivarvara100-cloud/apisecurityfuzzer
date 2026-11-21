import type { Exchange, Finding } from "../api/types";
import { pathOf, prettyBody, rolesFor, sameBodyAs, type Actor, type Role } from "../lib/evidence";

const BADGE: Record<Actor, string> = { a: "A", b: "B", token: "T", none: "–" };
const BADGE_NAME: Record<Actor, string> = {
  a: "Sent with account A's token",
  b: "Sent with account B's token",
  token: "Sent with a test account's token",
  none: "Sent without a token",
};

function Headers({ title, headers }: { title: string; headers: Record<string, string> }) {
  return (
    <div className="headers__col">
      <h4>{title}</h4>
      {Object.entries(headers).map(([k, v]) => (
        <div className="headers__row" key={k}>
          <span>{k}:</span> {v}
        </div>
      ))}
    </div>
  );
}

function ExchangeRow({
  ex,
  role,
  index,
  same,
  sameRole,
}: {
  ex: Exchange;
  role: Role;
  index: number;
  same: number;
  sameRole?: Role;
}) {
  const status = ex.response?.status_code;
  const reqBody = prettyBody(ex.request.body);
  const resBody = prettyBody(ex.response?.body);
  return (
    // B getting exactly what A got is the BOLA leak itself; that card is marked so it can flash.
    <li className={`exchange exchange--${role.actor}${role.actor === "b" && sameRole?.actor === "a" ? " exchange--leak" : ""}`}>
      <div className="exchange__who">
        <span className="exchange__badge" role="img" aria-label={BADGE_NAME[role.actor]}>
          {BADGE[role.actor]}
        </span>
        <span className="exchange__label">
          <span className="visually-hidden">Request {index + 1}: </span>
          {role.label}
        </span>
      </div>
      <div className="exchange__card">
        <div className="exchange__line">
          <span className="exchange__req">
            <b>{ex.request.method}</b>
            {pathOf(ex.request.url)}
          </span>
          {status !== undefined ? (
            <span className={`exchange__status exchange__status--${String(status)[0]}`}>{status}</span>
          ) : (
            <span className="exchange__status exchange__status--5">{ex.error ?? "no answer"}</span>
          )}
        </div>
        <div className={`exchange__pane${reqBody ? "" : " exchange__pane--single"}`}>
          {reqBody && (
            <div className="exchange__body">
              <div className="exchange__body-label">Sent</div>
              <pre className="exchange__code">{reqBody}</pre>
            </div>
          )}
          <div className="exchange__body">
            <div className="exchange__body-label">
              Answer{ex.response?.truncated ? " (shortened)" : ""}
            </div>
            <pre className="exchange__code">{resBody || <span className="muted">empty body</span>}</pre>
          </div>
        </div>
        {same >= 0 && sameRole && (
          <p className="exchange__same">Same answer as “{sameRole.label}”</p>
        )}
        <details className="exchange__headers">
          <summary>Headers</summary>
          <div className="headers">
            <Headers title="Request" headers={ex.request.headers} />
            {ex.response && <Headers title="Response" headers={ex.response.headers} />}
          </div>
        </details>
      </div>
    </li>
  );
}

export function Evidence({ finding }: { finding: Finding }) {
  const roles = rolesFor(finding);
  if (finding.evidence.length === 0) return <p className="muted">This finding has no recorded requests.</p>;
  return (
    <ol className="timeline">
      {finding.evidence.map((ex, i) => {
        const same = sameBodyAs(finding.evidence, i);
        return (
          <ExchangeRow
            key={i}
            ex={ex}
            role={roles[i]}
            index={i}
            same={same}
            sameRole={same >= 0 ? roles[same] : undefined}
          />
        );
      })}
    </ol>
  );
}
