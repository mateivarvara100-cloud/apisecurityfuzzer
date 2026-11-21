// Settings read at build time from VITE_* variables (see .env.example).

const env = import.meta.env;

export const API_MODE: "mock" | "live" = env.VITE_API_MODE === "live" ? "live" : "mock";

/** Supabase handles sign-in (Google, or e-mail and password). Both values are safe in a browser. */
export const SUPABASE_URL: string = env.VITE_SUPABASE_URL || "";
// Supabase's Connect dialog now names this the publishable key (sb_publishable_...); older projects
// call it the anon key. Either name works.
export const SUPABASE_ANON_KEY: string = env.VITE_SUPABASE_PUBLISHABLE_KEY || env.VITE_SUPABASE_ANON_KEY || "";

/**
 * supabase: real sign-in. mock: simulated, so the UI can be worked on; only in `npm run dev`.
 * off: a production build without Supabase settings, where sign-in is refused rather than faked.
 */
export const AUTH_MODE: "supabase" | "mock" | "off" =
  SUPABASE_URL && SUPABASE_ANON_KEY ? "supabase" : env.DEV ? "mock" : "off";

const DEFAULT_TARGET = "http://127.0.0.1:8000";

function demoTarget(): URL {
  try {
    const u = new URL(env.VITE_DEMO_TARGET || DEFAULT_TARGET);
    if (u.protocol === "http:" || u.protocol === "https:") return u;
  } catch {
    // fall through: a malformed setting must not take the whole app down
  }
  return new URL(DEFAULT_TARGET);
}

const target = demoTarget();

/** The demo target. The server holds the real allowlist; this copy only explains refusals early. */
export const DEMO_TARGET: string = target.origin;

export const ALLOWLIST: { host: string; label: string }[] = [{ host: target.host, label: "VulnShop lab" }];

/**
 * Limits the plan asks for ("a cap on scans per user per day and a small request burst size").
 * The plan gives no numbers; these are placeholders until the backend decides them.
 */
export const LIMITS = { scansPerDay: 5, burst: 15 };
