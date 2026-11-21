// Settings read at build time from VITE_* variables (see .env.example).

const env = import.meta.env;

export const API_MODE: "mock" | "live" = env.VITE_API_MODE === "live" ? "live" : "mock";

/** The scan backend (live mode), e.g. https://apifuzz-api.onrender.com. Empty if missing or malformed. */
export const API_URL: string = (() => {
  try {
    const u = new URL(env.VITE_API_URL || "");
    return u.protocol === "http:" || u.protocol === "https:" ? u.origin : "";
  } catch {
    return "";
  }
})();

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

/**
 * Google's OAuth web client id (public: it is in every Google sign-in URL). With it, sign-in uses
 * Google's own button, so Google's screen names this site; without it, the Supabase redirect.
 */
export const GOOGLE_CLIENT_ID: string = /^[\w-]+\.apps\.googleusercontent\.com$/.test(env.VITE_GOOGLE_CLIENT_ID || "")
  ? env.VITE_GOOGLE_CLIENT_ID
  : "";

/** Who runs this deployment, for the terms and privacy notice. Set both before going public. */
export const OPERATOR_NAME: string = (env.VITE_OPERATOR_NAME || "").trim();
export const CONTACT_EMAIL: string = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test((env.VITE_CONTACT_EMAIL || "").trim())
  ? env.VITE_CONTACT_EMAIL.trim()
  : "";
export const REPOSITORY_URL = "https://github.com/mateivarvara100-cloud/apisecurityfuzzer";

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
 * The limits preview mode pretends to have. In live mode the backend says what they are (GET /me);
 * these match its defaults.
 */
export const LIMITS = { scansPerDay: 5, burst: 15 };
