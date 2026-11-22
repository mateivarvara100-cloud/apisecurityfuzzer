// A scan while it runs on the server: which phase it is in, how far the checks have got, the last
// requests it sent, and a Cancel button. The page polls the server and passes each answer in.

import { CHECKS } from "../api/checks";
import type { JobPhase, ScanJob } from "../api/types";
import { plural } from "../lib/format";
import { Mark } from "./Mark";

const PHASES: { id: JobPhase; label: string }[] = [
  { id: "waking", label: "Waking the target" },
  { id: "spec", label: "Reading the spec" },
  { id: "login", label: "Signing in the test accounts" },
  { id: "checks", label: "Running the checks" },
  { id: "saving", label: "Saving the report" },
];

const checkName = (id: string | null) => CHECKS.find((c) => c.id === id)?.name ?? id ?? "";

export function ScanProgress({
  job,
  elapsed,
  onCancel,
  cancelling,
}: {
  job: ScanJob;
  elapsed: number;
  onCancel: () => void;
  cancelling: boolean;
}) {
  const p = job.progress;
  const at = PHASES.findIndex((ph) => ph.id === p.phase);
  const share = p.steps > 0 ? Math.min(1, p.step / p.steps) : 0;
  const stopping = job.cancelRequested || cancelling;

  return (
    <section className="progress" aria-labelledby="progress-title">
      <p className="progress__status">
        <Mark className="running__mark" />
        {/* Only the sentence is announced; the clock ticking every second is not. */}
        <span id="progress-title" role="status">
          {stopping ? `Stopping the scan of ${job.label}…` : `Scanning ${job.label}`}
        </span>
        <span className="progress__time" aria-hidden="true">
          {plural(elapsed, "second")}
        </span>
      </p>

      <ol className="progress__phases">
        {PHASES.map((ph, i) => (
          <li
            key={ph.id}
            className={`progress__phase${i < at ? " progress__phase--done" : ""}${i === at ? " progress__phase--now" : ""}`}
            aria-current={i === at ? "step" : undefined}
          >
            {ph.label}
            {ph.id === "checks" && i === at && p.check && <span className="progress__check">: {checkName(p.check)}</span>}
          </li>
        ))}
      </ol>

      {p.steps > 0 && (
        <div className="progress__bar-wrap">
          <div
            className="progress__bar"
            role="progressbar"
            aria-label="Checks done"
            aria-valuemin={0}
            aria-valuemax={p.steps}
            aria-valuenow={p.step}
            aria-valuetext={`${p.step} of ${p.steps} steps`}
          >
            <span className="progress__fill" style={{ transform: `scaleX(${share})` }} />
          </div>
          <span className="progress__count">
            {p.step} / {p.steps} steps · {plural(p.requestsSent, "request")} sent (stops at {p.maxRequests})
          </span>
        </div>
      )}

      {p.recent.length > 0 && (
        <div className="ticker" aria-hidden="true">
          <p className="ticker__label">Latest requests from the scan server</p>
          <ol className="ticker__lines">
            {p.recent.slice(-5).map((r, k) => (
              <li key={`${p.requestsSent}-${k}`} className="ticker__line">
                <b>{r.method}</b>
                <span className="ticker__path">{r.path}</span>
                <span className={`ticker__status ticker__status--${String(r.status ?? 5)[0]}`}>{r.status ?? "—"}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="progress__actions">
        <button type="button" className="button button--quiet" onClick={onCancel} disabled={stopping}>
          {stopping ? "Stopping…" : "Cancel scan"}
        </button>
        <span className="field__hint">
          {stopping
            ? "It stops after the step it's on, so no test data is left half-made. What it found so far is kept."
            : "You can leave this page: the scan keeps running, and its report appears in your history."}
        </span>
      </div>
    </section>
  );
}
