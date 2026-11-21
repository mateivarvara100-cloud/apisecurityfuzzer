// While a scan runs: a terminal-style feed of the requests going out. Without a backend there is
// nothing live to show, so it replays the requests of the recorded lab scan for the chosen checks,
// and says so. Decorative: screen readers get the "Scanning…" status line instead.

import { useEffect, useMemo, useState } from "react";
import { SAMPLE_REPORT } from "../api/service";
import type { CheckId } from "../api/types";
import { pathOf } from "../lib/evidence";
import { prefersReducedMotion } from "../lib/motion";

const VISIBLE = 5;
const EVERY_MS = 120;

export function RequestTicker({ checks }: { checks: CheckId[] }) {
  const lines = useMemo(
    () =>
      SAMPLE_REPORT.findings
        .filter((f) => checks.includes(f.check as CheckId))
        .flatMap((f) =>
          f.evidence.map((e) => ({
            method: e.request.method,
            path: pathOf(e.request.url),
            status: e.response?.status_code,
          })),
        ),
    [checks],
  );
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (prefersReducedMotion() || lines.length === 0) return;
    const id = setInterval(() => setCount((n) => n + 1), EVERY_MS);
    return () => clearInterval(id);
  }, [lines.length]);

  if (lines.length === 0 || prefersReducedMotion()) return null;
  const shown = Math.min(count, VISIBLE);
  const first = count - shown;

  return (
    <div className="ticker" aria-hidden="true">
      <p className="ticker__label">Replaying requests from the recorded lab scan</p>
      <ol className="ticker__lines">
        {Array.from({ length: shown }, (_, k) => {
          const n = first + k;
          const line = lines[n % lines.length];
          return (
            <li key={n} className="ticker__line">
              <b>{line.method}</b>
              <span className="ticker__path">{line.path}</span>
              <span className={`ticker__status ticker__status--${String(line.status ?? 5)[0]}`}>
                {line.status ?? "—"}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
