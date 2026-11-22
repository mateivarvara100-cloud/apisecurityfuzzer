// /compare?base=<earlier scan>&head=<later scan>: what changed between two scans of one target.

import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { checkName, severityLabel } from "../api/checks";
import { isJob, scans } from "../api/service";
import type { Finding, ScanRecord } from "../api/types";
import { useSession } from "../auth/session";
import { FuzzText } from "../components/FuzzText";
import { compare } from "../lib/compare";
import { dateTime, hostOf, plural } from "../lib/format";

const GROUPS = [
  { key: "fresh", title: "New", empty: "Nothing new.", hint: "Found by the later scan, not the earlier one." },
  { key: "fixed", title: "Fixed", empty: "Nothing fixed.", hint: "Gone, and the later scan tested it again." },
  { key: "open", title: "Still open", empty: "Nothing carried over.", hint: "Found by both scans." },
  {
    key: "unchecked",
    title: "Not re-tested",
    empty: "",
    hint: "Gone from the later scan, but it didn't test this again (the check wasn't run, the scan stopped early, or the endpoint went untested). Not known to be fixed.",
  },
] as const;

function FindingRow({ f, scanId }: { f: Finding; scanId: string }) {
  return (
    <li className="compare__item">
      <span className={`sev sev--${f.severity}`}>{severityLabel(f.severity)}</span>
      <span className="compare__main">
        <span className="compare__title">{f.title}</span>
        <span className="compare__where">
          <code>{f.endpoint}</code> · {checkName(f.check)} ·{" "}
          <Link to={`/scans/${encodeURIComponent(scanId)}`}>report</Link>
        </span>
      </span>
    </li>
  );
}

export function Compare() {
  const { session } = useSession();
  const token = session?.accessToken ?? "";
  const [params, setParams] = useSearchParams();
  const baseId = params.get("base") ?? "";
  const headId = params.get("head") ?? "";
  const [history, setHistory] = useState<ScanRecord[] | null>(null);
  const [extra, setExtra] = useState<ScanRecord[]>([]); // asked for, but not in the history list
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    let current = true;
    scans
      .listScans(token)
      .then(async (list) => {
        const missing = [baseId, headId].filter((id) => id && !list.some((s) => s.id === id));
        const found = await Promise.all(missing.map((id) => scans.getScan(id, token).catch(() => null)));
        if (!current) return;
        setExtra(found.filter((s): s is ScanRecord => !!s && !isJob(s)));
        setHistory(list);
      })
      .catch((err: Error) => current && setFailure(err.message));
    return () => {
      current = false;
    };
  }, [token, baseId, headId]);

  const all = useMemo(() => [...(history ?? []), ...extra], [history, extra]);
  const base = all.find((s) => s.id === baseId) ?? null;
  const head = all.find((s) => s.id === headId) ?? null;
  // Earlier first, whatever order the link gave them in.
  const [earlier, later] = base && head && base.createdAt > head.createdAt ? [head, base] : [base, head];
  const sameTarget = useMemo(
    () => (later ? all.filter((s) => s.target === later.target).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) : []),
    [all, later],
  );
  const result = earlier && later ? compare(earlier.report, later.report) : null;

  function choose(which: "base" | "head", id: string) {
    const next = new URLSearchParams(params);
    next.set(which, id);
    setParams(next, { replace: true });
  }

  if (failure) {
    return (
      <p className="notice notice--error" role="alert">
        {failure}
      </p>
    );
  }
  if (history === null) return <p className="muted">Loading the scans…</p>;
  if (!earlier || !later) {
    return (
      <div className="empty">
        <h1 className="empty__title">These scans aren't in your history</h1>
        <p className="empty__text">
          One of them may be older than 30 days. <Link to="/scans">Open your scan history</Link> and pick a scan to
          compare from there.
        </p>
      </div>
    );
  }

  // Each picker changes whichever address parameter holds the scan it shows.
  const paramOf = (s: ScanRecord): "base" | "head" => (s.id === baseId ? "base" : "head");
  const picker = (id: string, label: string, value: ScanRecord) => (
    <div className="field compare__pick">
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      <select id={id} className="input" value={value.id} onChange={(e) => choose(paramOf(value), e.target.value)}>
        {sameTarget.map((s) => (
          <option key={s.id} value={s.id}>
            {dateTime(s.createdAt)} · {plural(s.report.findings.length, "finding")}
          </option>
        ))}
      </select>
    </div>
  );

  return (
    <>
      <h1 className="page-title">
        <FuzzText text="Compare scans" />
      </h1>
      {earlier.target !== later.target ? (
        <p className="notice notice--error" role="alert">
          These two scans are of different targets ({hostOf(earlier.target)} and {hostOf(later.target)}), so their
          findings can't be matched. Pick two scans of the same target.
        </p>
      ) : (
        <p className="lede">
          Two scans of <code>{hostOf(later.target)}</code>. Findings are matched by check, endpoint and field, the same
          way the CLI's accepted-findings file matches them.
        </p>
      )}

      <div className="compare__picks">
        {picker("compare-earlier", "Earlier scan", earlier)}
        {picker("compare-later", "Later scan", later)}
      </div>

      {earlier.id === later.id ? (
        <p className="field__hint">That's the same scan twice. Pick an earlier one to compare against.</p>
      ) : (
        result && (
          <>
            <ul className="compare__summary" aria-label="Summary">
              {GROUPS.filter((g) => g.key !== "unchecked" || result.unchecked.length > 0).map((g) => (
                <li key={g.key} className={`compare__count compare__count--${g.key}`}>
                  <span className="compare__number">{result[g.key].length}</span> {g.title.toLowerCase()}
                </li>
              ))}
            </ul>
            {GROUPS.map((g) => {
              const list = result[g.key];
              if (g.key === "unchecked" && list.length === 0) return null;
              const from = g.key === "fixed" || g.key === "unchecked" ? earlier : later;
              return (
                <section key={g.key} className="compare__group" aria-labelledby={`compare-${g.key}`}>
                  <h2 className="section-title" id={`compare-${g.key}`}>
                    {g.title} <span className="compare__group-count">{list.length}</span>
                  </h2>
                  <p className="field__hint">{g.hint}</p>
                  {list.length === 0 ? (
                    <p className="muted">{g.empty}</p>
                  ) : (
                    <ul className="compare__list">
                      {list.map((f) => (
                        <FindingRow key={f.fingerprint} f={f} scanId={from.id} />
                      ))}
                    </ul>
                  )}
                </section>
              );
            })}
          </>
        )
      )}
    </>
  );
}
