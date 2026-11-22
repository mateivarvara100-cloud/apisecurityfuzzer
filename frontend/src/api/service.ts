// The one place the UI talks to the outside world. In preview (mock) mode it answers from the
// bundled sample scan of the VulnShop lab and keeps history in this browser. In live mode it
// calls the FastAPI backend with the Supabase access token; the backend runs the apifuzz engine
// against its own allowlist and keeps the history.

import sample from "../data/sample-scan.json";
import { API_MODE, API_URL, LAB, LIMITS } from "./config";
import type { CheckId, NewTarget, OwnTarget, Report, ScanRecord, ScanRequest, TargetList } from "./types";

export const SAMPLE_REPORT = sample as Report;

const FIELDS = ["target", "specUrl", "authorized", "checks", "limit", "label", "url", "tokenA", "tokenB"] as const;
type RefusalField = (typeof FIELDS)[number];

/** A refusal the user can act on. `field` names the form field it belongs to, if any. */
export class ScanRefused extends Error {
  constructor(
    message: string,
    readonly field?: RefusalField,
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

/** The user's own APIs: added here, approved by an admin, then offered in the scan form. */
export interface TargetService {
  list(accessToken: string): Promise<TargetList>;
  add(target: NewTarget, accessToken: string): Promise<OwnTarget>;
  remove(id: string, accessToken: string): Promise<void>;
}

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

/**
 * The same rules the server applies, checked first so a refusal can be explained in the form.
 * `allowed` lists the origins this user may scan: the lab and their approved APIs.
 */
export function precheck(req: ScanRequest, allowed: string[] = [LAB.url]): ScanRefused | null {
  for (const [value, field] of [
    [req.target, "target"],
    [req.specUrl, "specUrl"],
  ] as const) {
    if (hasCredentials(value)) {
      return new ScanRefused("Take the user name and password out of the address; scans log in as the test accounts.", field);
    }
  }
  const target = parse(req.target);
  if (!target) return new ScanRefused("Choose what to scan.", "target");
  if (!allowed.includes(target.origin)) {
    return new ScanRefused(`${target.host} isn't the lab or one of your approved APIs, so it can't be scanned.`, "target");
  }
  if (hostOf(req.specUrl) !== target.host) {
    return new ScanRefused("The spec is downloaded by the server too, so it has to be on the target's own address.", "specUrl");
  }
  if (req.checks.length === 0) return new ScanRefused("Choose at least one check to run.", "checks");
  const a = req.tokenA?.trim(), b = req.tokenB?.trim();
  if (a && b && a === b) {
    return new ScanRefused("Accounts A and B need different tokens: they have to be two different users.", "tokenB");
  }
  if (!req.authorized) {
    return new ScanRefused("Confirm that you own this target or have written permission to test it.", "authorized");
  }
  return null;
}

/** What the API form checks before sending; the server checks again, and resolves the address. */
export function precheckTarget(t: NewTarget): ScanRefused | null {
  const label = t.label.trim();
  if (!label || label.length > 60) return new ScanRefused("Give the API a name of 1 to 60 characters.", "label");
  const url = parse(t.url.trim());
  if (!url) return new ScanRefused("Enter the API's address, like https://api.example.com.", "url");
  if (url.protocol !== "https:") return new ScanRefused("Use an https:// address. Only APIs served over HTTPS can be scanned.", "url");
  if (url.username || url.password) return new ScanRefused("Take the user name and password out of the address.", "url");
  if (url.port && url.port !== "8443") return new ScanRefused("Only the standard HTTPS ports can be scanned: 443 or 8443.", "url");
  const spec = parse(t.specUrl.trim());
  if (!spec) return new ScanRefused("Enter the address of the API's OpenAPI spec.", "specUrl");
  if (spec.origin !== url.origin) {
    return new ScanRefused(`The spec has to be on the API's own address (${url.origin}), because the server downloads it with the same safety rules as the scan.`, "specUrl");
  }
  if (!t.authorized) return new ScanRefused("Confirm that you own this API or have written permission to test it.", "authorized");
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
    const refused = precheck(req, [LAB.url, ...readTargets().map((t) => new URL(t.url).origin)]);
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

// Preview mode: APIs are kept in this browser and approved at once, so the whole flow can be tried.
const TARGETS_KEY = "apifuzz-web:targets";

function readTargets(): OwnTarget[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(TARGETS_KEY) ?? "[]");
    return Array.isArray(parsed) ? (parsed as OwnTarget[]).filter((t) => t && typeof t.id === "string") : [];
  } catch {
    return [];
  }
}

function writeTargets(targets: OwnTarget[]): void {
  try {
    localStorage.setItem(TARGETS_KEY, JSON.stringify(targets));
  } catch {
    // storage blocked: the list lasts until the page reloads
  }
}

const mockTargets: TargetService = {
  async list() {
    return { targets: readTargets(), maxTargets: 3, scansPerTargetPerDay: 3 };
  },
  async add(t) {
    const refused = precheckTarget(t);
    if (refused) throw refused;
    const current = readTargets();
    const url = new URL(t.url.trim()).origin;
    if (current.some((x) => x.url === url)) throw new ScanRefused("You've already added that API.", "url");
    if (current.length >= 3) throw new ScanRefused("You can have 3 APIs at most. Remove one to add another.", "limit");
    const target: OwnTarget = {
      id: crypto.randomUUID(),
      label: t.label.trim(),
      url,
      specUrl: t.specUrl.trim(),
      status: "approved",
      note: null,
      createdAt: new Date().toISOString(),
      scansLeftToday: 3,
    };
    writeTargets([...current, target]);
    return target;
  },
  async remove(id) {
    writeTargets(readTargets().filter((t) => t.id !== id));
  },
};

// ---- live -------------------------------------------------------------------------------

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
    // The form has already prechecked against this user's targets; the server checks everything again.
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

const isTarget = (t: unknown): t is OwnTarget => {
  const x = t as OwnTarget | null;
  return !!x && typeof x.id === "string" && typeof x.url === "string" && typeof x.status === "string";
};

const liveTargets: TargetService = {
  async list(token) {
    const { status, body } = await call("/targets", token);
    const b = body as Partial<TargetList> | null;
    if (status !== 200 || !b || !Array.isArray(b.targets)) throw new ServiceError(refusal(status, body).message);
    return {
      targets: b.targets.filter(isTarget),
      maxTargets: typeof b.maxTargets === "number" ? b.maxTargets : 3,
      scansPerTargetPerDay: typeof b.scansPerTargetPerDay === "number" ? b.scansPerTargetPerDay : 3,
    };
  },
  async add(t, token) {
    const refused = precheckTarget(t);
    if (refused) throw refused;
    const { status, body } = await call("/targets", token, { method: "POST", body: JSON.stringify(t) });
    if (status !== 201 || !isTarget(body)) throw refusal(status, body);
    return body;
  },
  async remove(id, token) {
    const { status, body } = await call(`/targets/${encodeURIComponent(id)}`, token, { method: "DELETE" });
    if (status !== 204 && status !== 404) throw new ServiceError(refusal(status, body).message);
  },
};

export const scans: ScanService = API_MODE === "live" ? liveService : mockService;
export const targets: TargetService = API_MODE === "live" ? liveTargets : mockTargets;
