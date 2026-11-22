// The JSON report apifuzz writes with --json-out (schema_version 2). These types mirror
// src/apifuzz/report.py and finding.py; the web app only reads the report, it never builds one.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type CheckId = "auth-required" | "bola" | "injection" | "mass-assignment" | "rate-limit";

export interface CapturedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

export interface CapturedResponse {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
}

export interface Exchange {
  request: CapturedRequest;
  response: CapturedResponse | null;
  elapsed_ms?: number;
  error?: string | null;
}

export interface Finding {
  check: string;
  owasp: string;
  severity: Severity;
  title: string;
  endpoint: string; // "METHOD /path"
  detail: string;
  remediation: string;
  evidence: Exchange[];
  key: string;
  accepted: boolean;
  accepted_reason: string;
  fingerprint: string;
}

export interface Coverage {
  check: string;
  tested: number;
  not_tested: number;
  not_applicable: number;
  notes: string[];
}

export interface Report {
  schema_version: number;
  tool_version: string;
  target: string;
  started_at: string; // ISO 8601
  duration_s: number;
  requests_sent: number;
  findings: Finding[];
  errors: string[];
  checks_run: string[];
  endpoints_scanned: number;
  coverage: Coverage[];
  incomplete: boolean;
}

/** One scan as the web app stores it: the request that started it plus the report it produced. */
export interface ScanRecord {
  id: string;
  status?: "done";
  target: string;
  specUrl: string;
  checks: CheckId[];
  createdAt: string;
  report: Report;
}

/** A scan while it runs in the background on the server, or one that ended without a report. */
export type JobStatus = "running" | "done" | "failed" | "cancelled";

/** waking the target, reading the spec, logging in the test accounts, running checks, saving */
export type JobPhase = "waking" | "spec" | "login" | "checks" | "saving";

export interface ScanJob {
  id: string;
  status: JobStatus;
  target: string;
  label: string;
  checks: CheckId[];
  createdAt: string;
  error: string | null;
  cancelRequested: boolean;
  stoppedEarly: boolean; // cancelled once the checks had started: the report is partial
  progress: {
    phase: JobPhase;
    check: string | null;
    step: number;
    steps: number;
    requestsSent: number;
    maxRequests: number;
    recent: { method: string; path: string; status: number | null }[]; // paths only, no query
  };
}

export interface ScanRequest {
  target: string;
  specUrl: string;
  checks: CheckId[];
  authorized: boolean;
  // Bearer tokens of two test accounts, only for the user's own API. Sent for this scan only;
  // the server never stores them.
  tokenA?: string;
  tokenB?: string;
}

/** A user's own API. An admin approves or rejects it by hand; only approved ones can be scanned. */
export type TargetStatus = "pending" | "approved" | "rejected";

/** How a user proves they control their API: publish `line` in a file at `url`. */
export interface Proof {
  url: string;
  line: string;
}

export interface OwnTarget {
  id: string;
  label: string;
  url: string; // https origin
  specUrl: string | null; // null when the spec was uploaded
  specName: string | null; // the uploaded file's name
  status: TargetStatus;
  note: string | null; // the admin's note, usually with a rejection
  createdAt: string;
  verifiedAt: string | null; // proven by the file; null if approved by an admin (or not yet)
  proof?: Proof; // while pending, and while a proven API is kept (it's checked before every scan)
  scansLeftToday?: number; // approved ones only
}

export interface TargetList {
  targets: OwnTarget[];
  maxTargets: number;
  scansPerTargetPerDay: number;
}

/** A spec: linked, or uploaded as a file's text. Exactly one is set. */
export type SpecSource = { specUrl: string; spec?: undefined } | { spec: { name: string; text: string }; specUrl?: undefined };

export type NewTarget = {
  label: string;
  url: string;
  authorized: boolean;
} & SpecSource;
