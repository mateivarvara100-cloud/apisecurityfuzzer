// The one place the UI talks to the outside world. In preview (mock) mode it answers from the
// bundled sample scan of the VulnShop lab and keeps history in this browser. In live mode it
// calls the FastAPI backend with the Supabase access token; the backend runs the apifuzz engine
// against its own allowlist and keeps the history.

import sample from "../data/sample-scan.json";
import { ALLOWLIST, API_MODE, API_URL, LIMITS } from "./config";
import type { CheckId, Report, ScanRecord, ScanRequest } from "./types";

export const SAMPLE_REPORT = sample as Report;

/** A refusal the user can act on. `field` names the form field it belongs to, if any. */
export class ScanRefused extends Error {
  constructor(
    message: string,
    readonly field?: "target" | "specUrl" | "authorized" | "checks" | "limit",
  ) {
    super(message);
  }
}

/** `left` is null when the account has no daily limit (an admin). */
export interface Limits {
  left: number | null;
  burst: number;
}

export interface ScanService {
  startScan(req: ScanRequest, accessToken: string): Promise<ScanRecord>;
  listScans(accessToken: string): Promise<ScanRecord[]>;
  getScan(id: string, accessToken: string): Promise<ScanRecord | null>;
  limits(accessToken: string): Promise<Limits>;
}

const allowedHosts = () => ALLOWLIST.map((a) => a.host);

function parse(url: string): URL | null {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

const hostOf = (url: string) => parse(url)?.host ?? null;

/** "http://user:pass@host" would send those credentials with every request. */
const hasCredentials = (url: string) => {
  const u = parse(url);
  return !!u && (u.username !== "" || u.password !== "");
};

/** The same rules the server applies, checked first so a refusal can be explained in the form. */
export function precheck(req: ScanRequest): ScanRefused | null {
  const allowed = allowedHosts();
  for (const [value, field] of [
    [req.target, "target"],
    [req.specUrl, "specUrl"],
  ] as const) {
    if (hasCredentials(value)) {
      return new ScanRefused("Take the user name and password out of the address; scans log in as the test accounts.", field);
    }
  }
  const target = hostOf(req.target);
  if (!target) return new ScanRefused("Enter the target as a full address, like http://127.0.0.1:8000.", "target");
  if (!allowed.includes(target)) {
    return new ScanRefused(
      `${target} is not on this server's allowlist, so it can't be scanned. Allowed: ${allowed.join(", ")}.`,
      "target",
    );
  }
  const spec = hostOf(req.specUrl);
  if (!spec) return new ScanRefused("Enter the spec as a full address, like http://127.0.0.1:8000/openapi.json.", "specUrl");
  if (!allowed.includes(spec)) {
    return new ScanRefused(
      `The spec is downloaded by the server too, so its host must be allowed. ${spec} is not on the allowlist.`,
      "specUrl",
    );
  }
  if (req.checks.length === 0) return new ScanRefused("Choose at least one check to run.", "checks");
  if (!req.authorized) {
    return new ScanRefused("Confirm that you own this target or have written permission to test it.", "authorized");
  }
  return null;
}

// ---- mock -------------------------------------------------------------------------------

const HISTORY_KEY = "apifuzz-web:scans";

/** A scan with a report the UI can show; anything else (an older format, a hand edit) is dropped. */
const isScanRecord = (s: unknown): s is ScanRecord => {
  const r = s as ScanRecord | null;
  return (
    !!r &&
    typeof r.id === "string" &&
    typeof r.createdAt === "string" &&
    !!r.report &&
    Array.isArray(r.report.findings) &&
    Array.isArray(r.report.coverage)
  );
};

function readHistory(): ScanRecord[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter(isScanRecord) : [];
  } catch {
    return [];
  }
}

function writeHistory(scans: ScanRecord[]): void {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(scans));
  } catch {
    // storage blocked (private window): history just won't survive a reload
  }
}

/** The sample report cut down to the checks that were asked for, as if only those had run. */
function reportFor(checks: CheckId[], startedAt: string): Report {
  const keep = (id: string) => checks.includes(id as CheckId);
  return {
    ...SAMPLE_REPORT,
    started_at: startedAt,
    findings: SAMPLE_REPORT.findings.filter((f) => keep(f.check)),
    coverage: SAMPLE_REPORT.coverage.filter((c) => keep(c.check)),
    checks_run: SAMPLE_REPORT.checks_run.filter(keep),
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Days run midnight to midnight UTC, as on the server.
const utcDay = (iso: string) => new Date(iso).toISOString().slice(0, 10);
const todayCount = (scans: ScanRecord[]) => {
  const today = utcDay(new Date().toISOString());
  return scans.filter((s) => utcDay(s.createdAt) === today).length;
};

const mockService: ScanService = {
  async startScan(req) {
    const refused = precheck(req);
    if (refused) throw refused;
    const history = readHistory();
    if (todayCount(history) >= LIMITS.scansPerDay) {
      throw new ScanRefused(`You've used all ${LIMITS.scansPerDay} scans for today. The count resets at midnight UTC.`, "limit");
    }
    await sleep(1800); // a real scan of the lab takes a few seconds
    const createdAt = new Date().toISOString();
    const record: ScanRecord = {
      id: crypto.randomUUID().slice(0, 8),
      target: req.target,
      specUrl: req.specUrl,
      checks: req.checks,
      createdAt,
      report: reportFor(req.checks, createdAt),
    };
    writeHistory([record, ...history]);
    return record;
  },
  async listScans() {
    return readHistory();
  },
  async getScan(id) {
    return readHistory().find((s) => s.id === id) ?? null;
  },
  async limits() {
    return { left: Math.max(0, LIMITS.scansPerDay - todayCount(readHistory())), burst: LIMITS.burst };
  },
};

// ---- live -------------------------------------------------------------------------------

const FIELDS = ["target", "specUrl", "authorized", "checks", "limit"] as const;
type RefusalField = (typeof FIELDS)[number];

/** A failure the form can't fix: the server is away, or the sign-in ran out. */
export class ServiceError extends Error {}

async function call(path: string, token: string, init: RequestInit = {}): Promise<{ status: number; body: unknown }> {
  if (!API_URL) throw new ServiceError("This deployment has no scan server configured (VITE_API_URL).");
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...(init.body ? { "Content-Type": "application/json" } : {}) },
      credentials: "omit", // the sign-in goes in the header; no cookies are sent
      cache: "no-store",
      redirect: "error",
    });
  } catch {
    throw new ServiceError(
      "Can't reach the scan server. On free hosting it sleeps when idle and takes up to a minute to wake; try again shortly.",
    );
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // not JSON: the status below says what happened
  }
  if (res.status === 401) throw new ServiceError("Your sign-in has expired. Sign out, then sign in again.");
  return { status: res.status, body };
}

function refusal(status: number, body: unknown): ScanRefused {
  const b = (body ?? {}) as { detail?: unknown; field?: unknown };
  const detail = typeof b.detail === "string" ? b.detail : `The server answered ${status}. Try again in a minute.`;
  const field = FIELDS.includes(b.field as RefusalField) ? (b.field as RefusalField) : undefined;
  return new ScanRefused(detail, field);
}

const liveService: ScanService = {
  async startScan(req, token) {
    const refused = precheck(req);
    if (refused) throw refused;
    const { status, body } = await call("/scans", token, { method: "POST", body: JSON.stringify(req) });
    if (status !== 201 || !isScanRecord(body)) throw refusal(status, body);
    return body;
  },
  async listScans(token) {
    const { status, body } = await call("/scans", token);
    if (status !== 200 || !Array.isArray(body)) throw new ServiceError(refusal(status, body).message);
    return body.filter(isScanRecord);
  },
  async getScan(id, token) {
    const { status, body } = await call(`/scans/${encodeURIComponent(id)}`, token);
    if (status === 404) return null;
    if (status !== 200 || !isScanRecord(body)) throw new ServiceError(refusal(status, body).message);
    return body;
  },
  async limits(token) {
    const { status, body } = await call("/me", token);
    const me = body as { scansLeftToday?: unknown; burst?: unknown } | null;
    if (status !== 200 || !me) throw new ServiceError(refusal(status, body).message);
    return {
      left: typeof me.scansLeftToday === "number" ? me.scansLeftToday : null,
      burst: typeof me.burst === "number" ? me.burst : LIMITS.burst,
    };
  },
};

export const scans: ScanService = API_MODE === "live" ? liveService : mockService;
