import { SEVERITIES, severityLabel } from "../api/checks";
import type { Finding, Severity } from "../api/types";

export const dateTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });

export const seconds = (s: number) => (s < 10 ? `${s.toFixed(1)} s` : `${Math.round(s)} s`);

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function countBySeverity(findings: Finding[]): [Severity, number][] {
  return SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length] as [Severity, number]).filter(
    ([, n]) => n > 0,
  );
}

/** "2 critical, 6 high, 1 medium" */
export function severitySummary(findings: Finding[]): string {
  return countBySeverity(findings)
    .map(([s, n]) => `${n} ${severityLabel(s).toLowerCase()}`)
    .join(", ");
}

export const hostOf = (url: string) => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};
