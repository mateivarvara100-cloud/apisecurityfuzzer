// The one place the UI talks to the outside world. Today only the mock exists: it answers from
// the bundled sample scan of the VulnShop lab and keeps history in this browser. The live
// version will POST to the FastAPI backend with the Supabase access token; the backend runs the
// apifuzz engine against its own allowlist and stores the result in Supabase.

import sample from "../data/sample-scan.json";
import { ALLOWLIST, API_MODE, LIMITS } from "./config";
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

export interface ScanService {
  startScan(req: ScanRequest, accessToken: string): Promise<ScanRecord>;
  listScans(accessToken: string): Promise<ScanRecord[]>;
  getScan(id: string, accessToken: string): Promise<ScanRecord | null>;
  scansLeftToday(accessToken: string): Promise<number>;
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

function readHistory(): ScanRecord[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    // Anything that isn't a list of scans with a report (an older format, a hand edit) is dropped.
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (s): s is ScanRecord =>
        !!s && typeof s.id === "string" && !!s.report && Array.isArray(s.report.findings) && Array.isArray(s.report.coverage),
    );
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

const todayCount = (scans: ScanRecord[]) => {
  const today = new Date().toDateString();
  return scans.filter((s) => new Date(s.createdAt).toDateString() === today).length;
};

const mockService: ScanService = {
  async startScan(req) {
    const refused = precheck(req);
    if (refused) throw refused;
    const history = readHistory();
    if (todayCount(history) >= LIMITS.scansPerDay) {
      throw new ScanRefused(`You've used all ${LIMITS.scansPerDay} scans for today. The count resets at midnight.`, "limit");
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
  async scansLeftToday() {
    return Math.max(0, LIMITS.scansPerDay - todayCount(readHistory()));
  },
};

const liveService: ScanService = {
  async startScan() {
    throw new ScanRefused("The scan backend isn't connected yet. Set VITE_API_MODE=mock to use sample data.");
  },
  async listScans() {
    return [];
  },
  async getScan() {
    return null;
  },
  async scansLeftToday() {
    return 0;
  },
};

export const scans: ScanService = API_MODE === "live" ? liveService : mockService;
