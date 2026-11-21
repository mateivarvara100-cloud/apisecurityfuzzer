import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { severityLabel } from "../api/checks";
import { scans } from "../api/service";
import type { ScanRecord } from "../api/types";
import { useSession } from "../auth/session";
import { countBySeverity, dateTime, hostOf, seconds } from "../lib/format";
import { FuzzText } from "../components/FuzzText";

export function History() {
  const { session } = useSession();
  const [list, setList] = useState<ScanRecord[] | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    let current = true;
    scans
      .listScans(session?.accessToken ?? "")
      .then((l) => current && setList(l))
      .catch((err: Error) => current && setFailure(err.message));
    return () => {
      current = false;
    };
  }, [session]);

  return (
    <>
      <h1 className="page-title">
        <FuzzText text="Scan history" />
      </h1>
      {failure ? (
        <p className="notice notice--error" role="alert">
          {failure}
        </p>
      ) : list === null ? (
        <p className="lede">Loading…</p>
      ) : list.length === 0 ? (
        <div className="empty">
          <p className="empty__title">No scans yet</p>
          <p className="empty__text">
            <Link to="/">Start a scan</Link> of the VulnShop lab, and its report will be kept here.
          </p>
        </div>
      ) : (
        <div className="table-wrap table-wrap--page">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Started</th>
                <th scope="col">Target</th>
                <th scope="col">Findings</th>
                <th scope="col" className="num">
                  Took
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((s) => {
                const counts = countBySeverity(s.report.findings);
                return (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/scans/${s.id}`}>{dateTime(s.createdAt)}</Link>
                    </td>
                    <td>
                      <code>{hostOf(s.target)}</code>
                    </td>
                    <td>
                      {counts.length === 0 ? (
                        <span className="muted">None</span>
                      ) : (
                        <span className="sev-counts">
                          {counts.map(([sev, n]) => (
                            <span key={sev} className={`sev sev--${sev}`}>
                              {n} {severityLabel(sev).toLowerCase()}
                            </span>
                          ))}
                        </span>
                      )}
                    </td>
                    <td className="num">{seconds(s.report.duration_s)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
