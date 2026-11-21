import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { scans } from "../api/service";
import type { ScanRecord } from "../api/types";
import { useSession } from "../auth/session";
import { ReportView } from "../components/ReportView";

export function ScanReport() {
  const { id = "" } = useParams();
  const { session } = useSession();
  const [record, setRecord] = useState<ScanRecord | null | undefined>(undefined);

  useEffect(() => {
    scans.getScan(id, session?.accessToken ?? "").then(setRecord);
  }, [id, session]);

  if (record === undefined) return <p className="muted">Loading the report…</p>;
  if (record === null) {
    return (
      <div className="empty">
        <h1 className="empty__title">This scan isn't in your history</h1>
        <p className="empty__text">
          It may have been made in another browser. <Link to="/scans">Open your scan history</Link>.
        </p>
      </div>
    );
  }
  // Keyed by scan, so moving from one report to another starts at its first finding.
  return <ReportView key={record.id} report={record.report} />;
}
