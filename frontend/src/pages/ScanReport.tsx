// One scan. While it runs on the server this page shows its progress, asking every few seconds;
// once it is done it shows the report, with a link to compare it with the scan before it.

import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { API_MODE } from "../api/config";
import { isJob, scans } from "../api/service";
import type { ScanJob, ScanRecord } from "../api/types";
import { useSession } from "../auth/session";
import { ReportView } from "../components/ReportView";
import { ScanProgress } from "../components/ScanProgress";
import { dateTime } from "../lib/format";

const POLL_MS = 2500;

/** The scan of the same target just before this one, from the history (newest first). */
function previousOf(record: ScanRecord, history: ScanRecord[]): ScanRecord | null {
  const older = history.filter((s) => s.target === record.target && s.id !== record.id && s.createdAt < record.createdAt);
  return older[0] ?? null;
}

/** The server's reason as a sentence: a capital letter (unless it starts with an address) and a full stop. */
function sentence(text: string): string {
  const t = /^https?:\/\//i.test(text) ? text : text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(t) ? t : `${t}.`;
}

function Ended({ job }: { job: ScanJob }) {
  const cancelled = job.status === "cancelled";
  return (
    <div className="empty">
      <h1 className="empty__title">{cancelled ? "The scan was cancelled" : "The scan stopped"}</h1>
      <p className="empty__text">
        {job.error ? sentence(job.error) : "It ended without a report."}{" "}
        {job.progress.requestsSent > 0
          ? "It had reached the target, so it counts towards today's scans."
          : "Nothing was sent to the target, so it doesn't count towards today's scans."}{" "}
        <Link to="/">Start another scan</Link>
        .
      </p>
    </div>
  );
}

export function ScanReport() {
  const { id = "" } = useParams();
  const { session } = useSession();
  const token = session?.accessToken ?? "";
  const [scan, setScan] = useState<ScanRecord | ScanJob | null | undefined>(undefined);
  const [failure, setFailure] = useState<string | null>(null);
  const [lost, setLost] = useState(false);
  const [previous, setPrevious] = useState<ScanRecord | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const seenAt = useRef<number>(Date.now()); // when this page first saw the scan running

  const load = useCallback(
    () =>
      scans
        .getScan(id, token)
        .then((s) => setScan(s))
        .catch((err: Error) => setFailure(err.message)),
    [id, token],
  );

  useEffect(() => {
    setScan(undefined);
    setFailure(null);
    setLost(false);
    setPrevious(null);
    seenAt.current = Date.now();
    load();
  }, [load]);

  const running = isJob(scan) && scan.status === "running";

  // Ask for progress until the scan ends; then load what it left (the report, or its job).
  useEffect(() => {
    if (!running) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const ask = () => {
      scans
        .progress(id, token)
        .then((p) => {
          if (stopped) return;
          if (p === null) return setLost(true);
          if (p === "done" || p.status !== "running") return void load();
          setScan(p);
          timer = setTimeout(ask, POLL_MS);
        })
        .catch(() => {
          if (!stopped) timer = setTimeout(ask, POLL_MS * 2); // the server may be busy; keep trying
        });
    };
    timer = setTimeout(ask, POLL_MS);
    const clock = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      stopped = true;
      clearTimeout(timer);
      clearInterval(clock);
    };
  }, [running, id, token, load]);

  // A finished report: find the scan of the same target before it, for "Compare".
  useEffect(() => {
    if (!scan || isJob(scan)) return;
    let current = true;
    scans
      .listScans(token)
      .then((history) => current && setPrevious(previousOf(scan, history)))
      .catch(() => undefined); // the comparison link is extra; the report itself is shown anyway
    return () => {
      current = false;
    };
  }, [scan, token]);

  async function cancel() {
    setCancelling(true);
    try {
      setScan(await scans.cancel(id, token));
    } catch (err) {
      setFailure(err instanceof Error ? err.message : "The scan couldn't be cancelled. Try again.");
      setCancelling(false);
    }
  }

  if (failure) {
    return (
      <p className="notice notice--error" role="alert">
        {failure}
      </p>
    );
  }
  if (lost) {
    return (
      <div className="empty">
        <h1 className="empty__title">The scan server lost this scan</h1>
        <p className="empty__text">
          It was probably restarted while the scan ran, so the scan never finished. <Link to="/">Start it again</Link>.
        </p>
      </div>
    );
  }
  if (scan === undefined) return <p className="muted">Loading the report…</p>;
  if (scan === null) {
    return (
      <div className="empty">
        <h1 className="empty__title">This scan isn't in your history</h1>
        <p className="empty__text">
          {API_MODE === "live"
            ? "It may be older than 30 days, or belong to another account."
            : "It may have been made in another browser."}{" "}
          <Link to="/scans">Open your scan history</Link>.
        </p>
      </div>
    );
  }
  if (isJob(scan)) {
    if (scan.status !== "running") return <Ended job={scan} />;
    const started = Math.min(seenAt.current, Date.parse(scan.createdAt) || seenAt.current);
    return (
      <ScanProgress
        job={scan}
        elapsed={Math.max(0, Math.floor((now - started) / 1000))}
        onCancel={cancel}
        cancelling={cancelling}
      />
    );
  }
  const banner = previous && (
    <p className="report-compare">
      <Link to={`/compare?base=${encodeURIComponent(previous.id)}&head=${encodeURIComponent(scan.id)}`}>
        Compare with the scan before ({dateTime(previous.createdAt)})
      </Link>
    </p>
  );
  // Keyed by scan, so moving from one report to another starts at its first finding.
  return <ReportView key={scan.id} report={scan.report} banner={banner} />;
}
