// The one place the UI talks to the outside world. In preview (mock) mode it answers from the
// bundled sample scan of the VulnShop lab and keeps history in this browser. In live mode it
// calls the FastAPI backend with the Supabase access token; the backend runs the apifuzz engine
// against its own allowlist and keeps the history.
//
// A scan runs in the background: startScan answers at once with its job, and the page asks for
// progress every few seconds until it is done, then loads the report.

import sample from "../data/sample-scan.json";
import { pathOf } from "../lib/evidence";
import { API_MODE, API_URL, LAB, LIMITS } from "./config";
import type {
  CheckId,
  JobPhase,
  NewTarget,
  OwnTarget,
  Report,
  ScanJob,
  ScanRecord,
  ScanRequest,
  SpecSource,
  TargetList,
} from "./types";

export const SAMPLE_REPORT = sample as Report;

/** Where the proof of control is published; never a spec. */
const PROOF_PATH = "/.well-known/apifuzz-verify.txt";

/** The largest spec that can be uploaded, as the server counts it (UTF-8 bytes). */
export const MAX_SPEC_BYTES = 1_000_000;

const FIELDS = ["target", "specUrl", "spec", "authorized", "checks", "limit", "label", "url", "tokenA", "tokenB"] as const;
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
  running: { id: string; label: string } | null; // this account's scan that is still running
}

export interface ScanService {
  startScan(req: ScanRequest, accessToken: string): Promise<ScanJob>;
  listScans(accessToken: string): Promise<ScanRecord[]>;
  /** The report once the scan is done; its job while it runs or if it ended without one. */
  getScan(id: string, accessToken: string): Promise<ScanRecord | ScanJob | null>;
  /** How a running scan is going; "done" once its report is saved; null if the server lost it. */
  progress(id: string, accessToken: string): Promise<ScanJob | "done" | null>;
  cancel(id: string, accessToken: string): Promise<ScanJob>;
  limits(accessToken: string): Promise<Limits>;
}

/** The user's own APIs: added here, proven (or approved by an admin), then offered in the scan form. */
export interface TargetService {
  list(accessToken: string): Promise<TargetList>;
  add(target: NewTarget, accessToken: string): Promise<OwnTarget>;
  /** Look for the proof file on the API; approves it if the file is there. */
  verify(id: string, accessToken: string): Promise<OwnTarget>;
  replaceSpec(id: string, spec: SpecSource, accessToken: string): Promise<OwnTarget>;
  remove(id: string, accessToken: string): Promise<void>;
}

export const isJob = (x: ScanRecord | ScanJob | null | undefined): x is ScanJob =>
  !!x && "progress" in x && typeof (x as ScanJob).status === "string";

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
 * `allowed` lists the origins this user may scan: the lab and their approved APIs. A user's own
 * API is scanned with the spec stored with it, so its request may carry no spec address.
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
  if (req.specUrl && hostOf(req.specUrl) !== target.host) {
    return new ScanRefused("The spec is downloaded by the server too, so it has to be on the target's own address.", "specUrl");
  }
  if (req.checks.length === 0) return new ScanRefused("Choose at least one check to run.", "checks");
  const a = req.tokenA?.trim(),
    b = req.tokenB?.trim();
  if (a && b && a === b) {
    return new ScanRefused("Accounts A and B need different tokens: they have to be two different users.", "tokenB");
  }
  if (!req.authorized) {
    return new ScanRefused("Confirm that you own this target or have written permission to test it.", "authorized");
  }
  return null;
}

const utf8Bytes = (text: string) => new TextEncoder().encode(text).length;

/** A linked or uploaded spec, checked as far as the browser can; `origin` is the API's. */
export function precheckSpec(src: SpecSource, origin: string | null): ScanRefused | null {
  if (src.spec) {
    if (!src.spec.text.trim()) return new ScanRefused(`${src.spec.name} is empty.`, "spec");
    if (utf8Bytes(src.spec.text) > MAX_SPEC_BYTES) {
      return new ScanRefused(`${src.spec.name} is larger than 1 MB, the most that can be uploaded.`, "spec");
    }
    return null;
  }
  const spec = parse((src.specUrl ?? "").trim());
  if (!spec) return new ScanRefused("Enter the address of the API's OpenAPI spec, or upload the file.", "specUrl");
  if (spec.pathname === PROOF_PATH) {
    return new ScanRefused("That's the proof file's address, not the spec. Link the OpenAPI spec (often /openapi.json), or upload it.", "specUrl");
  }
  if (origin && spec.origin !== origin) {
    return new ScanRefused(
      `The spec has to be on the API's own address (${origin}), because the server downloads it with the same safety rules as the scan. Or upload the file.`,
      "specUrl",
    );
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
  const spec = precheckSpec(t, url.origin);
  if (spec) return spec;
  if (!t.authorized) return new ScanRefused("Confirm that you own this API or have written permission to test it.", "authorized");
  return null;
}

/** Just the spec part of a form, as the server wants it. */
const specBody = (src: SpecSource) => (src.spec ? { spec: src.spec } : { specUrl: (src.specUrl ?? "").trim() });

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
function reportFor(checks: CheckId[], startedAt: string, target: string): Report {
  const keep = (id: string) => checks.includes(id as CheckId);
  return {
    ...SAMPLE_REPORT,
    target,
    started_at: startedAt,
    findings: SAMPLE_REPORT.findings.filter((f) => keep(f.check)),
    coverage: SAMPLE_REPORT.coverage.filter((c) => keep(c.check)),
    checks_run: SAMPLE_REPORT.checks_run.filter(keep),
  };
}

/** A report that stopped partway, the way the engine marks one that was cancelled. */
function stoppedReport(report: Report, fraction: number): Report {
  const n = Math.floor(report.findings.length * fraction);
  return {
    ...report,
    findings: report.findings.slice(0, n),
    incomplete: true,
    errors: [...report.errors, "scan stopped early: cancelled by the user"],
  };
}

// Days run midnight to midnight UTC, as on the server.
const utcDay = (iso: string) => new Date(iso).toISOString().slice(0, 10);
const todayCount = (scans: ScanRecord[]) => {
  const today = utcDay(new Date().toISOString());
  return scans.filter((s) => utcDay(s.createdAt) === today).length;
};

// Preview mode's scans run in this tab, on a timer, through the same phases as the server's.
const mockJobs = new Map<string, ScanJob>();
const MOCK_TICK_MS = 220;
const MOCK_ENDPOINTS = SAMPLE_REPORT.endpoints_scanned;
const MOCK_FEED = SAMPLE_REPORT.findings.flatMap((f) =>
  f.evidence.map((e) => ({ method: e.request.method, path: pathOf(e.request.url), status: e.response?.status_code ?? null })),
);

function runMockJob(job: ScanJob, req: ScanRequest): void {
  const plan: JobPhase[] = ["waking", "spec", "login"];
  let tick = 0;
  const timer = setInterval(() => {
    tick += 1;
    const p = job.progress;
    if (job.cancelRequested && p.phase !== "checks" && p.phase !== "saving") {
      clearInterval(timer);
      job.status = "cancelled";
      job.error = "the scan was cancelled before the checks started.";
      return;
    }
    if (tick <= plan.length) {
      p.phase = plan[tick - 1];
      return;
    }
    if (p.phase !== "saving" && p.step < p.steps && !job.cancelRequested) {
      p.phase = "checks";
      p.check = job.checks[Math.min(job.checks.length - 1, Math.floor(p.step / MOCK_ENDPOINTS))];
      p.step += 1;
      for (let i = 0; i < 2; i++) {
        p.requestsSent += 1;
        p.recent = [...p.recent, MOCK_FEED[p.requestsSent % MOCK_FEED.length]].slice(-8);
      }
      return;
    }
    if (p.phase !== "saving") {
      p.phase = "saving";
      return;
    }
    clearInterval(timer);
    const full = reportFor(job.checks, job.createdAt, req.target);
    const report = job.cancelRequested ? stoppedReport(full, p.step / p.steps) : full;
    const record: ScanRecord = {
      id: job.id,
      status: "done",
      target: req.target,
      specUrl: req.specUrl,
      checks: job.checks,
      createdAt: job.createdAt,
      report: { ...report, requests_sent: p.requestsSent },
    };
    writeHistory([record, ...readHistory()]);
    job.status = "done";
    job.stoppedEarly = job.cancelRequested;
  }, MOCK_TICK_MS);
}

const snapshot = (job: ScanJob): ScanJob => ({ ...job, progress: { ...job.progress, recent: [...job.progress.recent] } });
const runningMock = () => [...mockJobs.values()].find((j) => j.status === "running") ?? null;

const mockService: ScanService = {
  async startScan(req) {
    const own = readTargets().filter((t) => t.status === "approved").map((t) => new URL(t.url).origin);
    const refused = precheck(req, [LAB.url, ...own]);
    if (refused) throw refused;
    const running = runningMock();
    if (running) throw new ScanRefused(`Your scan of ${running.label} is still running. Wait for it to finish, or cancel it.`);
    if (todayCount(readHistory()) >= LIMITS.scansPerDay) {
      throw new ScanRefused(`You've used all ${LIMITS.scansPerDay} scans for today. The count resets at midnight UTC.`, "limit");
    }
    const checks = req.checks;
    const job: ScanJob = {
      id: crypto.randomUUID(),
      status: "running",
      target: req.target,
      label: readTargets().find((t) => t.url === new URL(req.target).origin)?.label ?? LAB.label,
      checks,
      createdAt: new Date().toISOString(),
      error: null,
      cancelRequested: false,
      stoppedEarly: false,
      progress: { phase: "waking", check: null, step: 0, steps: checks.length * MOCK_ENDPOINTS, requestsSent: 0, maxRequests: 400, recent: [] },
    };
    mockJobs.set(job.id, job);
    runMockJob(job, req);
    return snapshot(job);
  },
  async listScans() {
    return readHistory();
  },
  async getScan(id) {
    const job = mockJobs.get(id);
    if (job && job.status !== "done") return snapshot(job);
    return readHistory().find((s) => s.id === id) ?? null;
  },
  async progress(id) {
    const job = mockJobs.get(id);
    if (job) return job.status === "done" ? "done" : snapshot(job);
    return readHistory().some((s) => s.id === id) ? "done" : null;
  },
  async cancel(id) {
    const job = mockJobs.get(id);
    if (!job) throw new ServiceError("No such running scan.");
    if (job.status === "running") job.cancelRequested = true;
    return snapshot(job);
  },
  async limits() {
    const running = runningMock();
    return {
      left: Math.max(0, LIMITS.scansPerDay - todayCount(readHistory())),
      burst: LIMITS.burst,
      running: running ? { id: running.id, label: running.label } : null,
    };
  },
};

// Preview mode: APIs are kept in this browser, and "Check now" approves at once, so the whole flow
// can be tried without a server (which is what would fetch the proof file).
const TARGETS_KEY = "apifuzz-web:targets";

function readTargets(): OwnTarget[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(TARGETS_KEY) ?? "[]");
    return Array.isArray(parsed)
      ? (parsed as OwnTarget[])
          .filter((t) => t && typeof t.id === "string")
          .map((t) => ({ ...t, specName: t.specName ?? null, verifiedAt: t.verifiedAt ?? null }))
      : [];
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

const mockProof = (url: string, id: string) => ({
  url: `${url}/.well-known/apifuzz-verify.txt`,
  line: `apifuzz-verify=${id.replace(/-/g, "")}`,
});

function updateTarget(id: string, change: (t: OwnTarget) => OwnTarget): OwnTarget {
  const all = readTargets();
  const i = all.findIndex((t) => t.id === id);
  if (i < 0) throw new ServiceError("No such API.");
  all[i] = change(all[i]);
  writeTargets(all);
  return all[i];
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
    const id = crypto.randomUUID();
    const target: OwnTarget = {
      id,
      label: t.label.trim(),
      url,
      specUrl: t.spec ? null : (t.specUrl ?? "").trim(),
      specName: t.spec ? t.spec.name : null,
      status: "pending",
      note: null,
      createdAt: new Date().toISOString(),
      verifiedAt: null,
      proof: mockProof(url, id),
    };
    writeTargets([...current, target]);
    return target;
  },
  async verify(id) {
    return updateTarget(id, (t) =>
      t.status === "pending" ? { ...t, status: "approved", verifiedAt: new Date().toISOString(), scansLeftToday: 3 } : t,
    );
  },
  async replaceSpec(id, src) {
    const current = readTargets().find((t) => t.id === id);
    const refused = precheckSpec(src, current?.url ?? null);
    if (refused) throw refused;
    // Preview mode keeps only the file's name: nothing is scanned with it.
    return updateTarget(id, (t) => ({
      ...t,
      specUrl: src.spec ? null : (src.specUrl ?? "").trim(),
      specName: src.spec ? src.spec.name : null,
    }));
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

const asJob = (body: unknown): ScanJob | null => (isJob(body as ScanJob) ? (body as ScanJob) : null);

const liveService: ScanService = {
  async startScan(req, token) {
    // The form has already prechecked against this user's targets; the server checks everything again.
    const { status, body } = await call("/scans", token, { method: "POST", body: JSON.stringify(req) });
    const job = asJob(body);
    if (status !== 202 || !job) throw refusal(status, body);
    return job;
  },
  async listScans(token) {
    const { status, body } = await call("/scans", token);
    if (status !== 200 || !Array.isArray(body)) throw new ServiceError(refusal(status, body).message);
    return body.filter(isScanRecord);
  },
  async getScan(id, token) {
    const { status, body } = await call(`/scans/${encodeURIComponent(id)}`, token);
    if (status === 404) return null;
    if (status === 200 && isScanRecord(body)) return body;
    const job = asJob(body);
    if (status === 200 && job) return job;
    throw new ServiceError(refusal(status, body).message);
  },
  async progress(id, token) {
    const { status, body } = await call(`/scans/${encodeURIComponent(id)}/progress`, token);
    if (status === 404) return null;
    if (status === 200 && (body as { status?: unknown } | null)?.status === "done") return "done";
    const job = asJob(body);
    if (status === 200 && job) return job.status === "done" ? "done" : job;
    throw new ServiceError(refusal(status, body).message);
  },
  async cancel(id, token) {
    const { status, body } = await call(`/scans/${encodeURIComponent(id)}/cancel`, token, { method: "POST" });
    const job = asJob(body);
    if (status !== 202 || !job) throw new ServiceError(refusal(status, body).message);
    return job;
  },
  async limits(token) {
    const { status, body } = await call("/me", token);
    const me = body as { scansLeftToday?: unknown; burst?: unknown; runningScan?: unknown } | null;
    if (status !== 200 || !me) throw new ServiceError(refusal(status, body).message);
    const running = me.runningScan as { id?: unknown; label?: unknown } | null | undefined;
    return {
      left: typeof me.scansLeftToday === "number" ? me.scansLeftToday : null,
      burst: typeof me.burst === "number" ? me.burst : LIMITS.burst,
      running:
        running && typeof running.id === "string" && typeof running.label === "string"
          ? { id: running.id, label: running.label }
          : null,
    };
  },
};

const isTarget = (t: unknown): t is OwnTarget => {
  const x = t as OwnTarget | null;
  return !!x && typeof x.id === "string" && typeof x.url === "string" && typeof x.status === "string";
};

/** Fills in fields an older server leaves out, so the page never reads undefined. */
const normalTarget = (t: OwnTarget): OwnTarget => ({ ...t, specUrl: t.specUrl ?? null, specName: t.specName ?? null, verifiedAt: t.verifiedAt ?? null });

const liveTargets: TargetService = {
  async list(token) {
    const { status, body } = await call("/targets", token);
    const b = body as Partial<TargetList> | null;
    if (status !== 200 || !b || !Array.isArray(b.targets)) throw new ServiceError(refusal(status, body).message);
    return {
      targets: b.targets.filter(isTarget).map(normalTarget),
      maxTargets: typeof b.maxTargets === "number" ? b.maxTargets : 3,
      scansPerTargetPerDay: typeof b.scansPerTargetPerDay === "number" ? b.scansPerTargetPerDay : 3,
    };
  },
  async add(t, token) {
    const refused = precheckTarget(t);
    if (refused) throw refused;
    const payload = { label: t.label, url: t.url, authorized: t.authorized, ...specBody(t) };
    const { status, body } = await call("/targets", token, { method: "POST", body: JSON.stringify(payload) });
    if (status !== 201 || !isTarget(body)) throw refusal(status, body);
    return normalTarget(body);
  },
  async verify(id, token) {
    const { status, body } = await call(`/targets/${encodeURIComponent(id)}/verify`, token, { method: "POST" });
    if (status !== 200 || !isTarget(body)) throw refusal(status, body);
    return normalTarget(body);
  },
  async replaceSpec(id, src, token) {
    const { status, body } = await call(`/targets/${encodeURIComponent(id)}/spec`, token, {
      method: "PUT",
      body: JSON.stringify(specBody(src)),
    });
    if (status !== 200 || !isTarget(body)) throw refusal(status, body);
    return normalTarget(body);
  },
  async remove(id, token) {
    const { status, body } = await call(`/targets/${encodeURIComponent(id)}`, token, { method: "DELETE" });
    if (status !== 204 && status !== 404) throw new ServiceError(refusal(status, body).message);
  },
};

export const scans: ScanService = API_MODE === "live" ? liveService : mockService;
export const targets: TargetService = API_MODE === "live" ? liveTargets : mockTargets;
