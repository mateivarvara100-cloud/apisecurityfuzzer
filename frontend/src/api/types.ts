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
  target: string;
  specUrl: string;
  checks: CheckId[];
  createdAt: string;
  report: Report;
}

export interface ScanRequest {
  target: string;
  specUrl: string;
  checks: CheckId[];
  authorized: boolean;
}
