import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { AUTH_MODE, SUPABASE_ANON_KEY, SUPABASE_URL } from "../api/config";

const AUTH_ERROR_PARAMS = ["error", "error_code", "error_description"];

/**
 * Why the last sign-in redirect came back refused, if it did. Supabase puts the reason in the
 * address (e.g. error_code=signup_disabled). Only messages written here are shown: the address can
 * be typed by anyone, so its own text (error_description) is never put on the page.
 */
function readRedirectError(): string | null {
  if (typeof window === "undefined") return null;
  const search = new URLSearchParams(window.location.search);
  const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const get = (k: string) => search.get(k) ?? hash.get(k);
  if (!get("error") && !get("error_code")) return null;

  const code = get("error_code") ?? "";
  const description = get("error_description") ?? "";
  if (code === "signup_disabled" || /signups? not allowed/i.test(description)) {
    return "New accounts can't be created right now. If you already have one, sign in with it.";
  }
  if (get("error") === "access_denied") return "Google sign-in was cancelled or refused. Try again.";
  return "Sign-in didn't finish. Try again.";
}

/** Take the error out of the address so it isn't shown again on reload or kept in history. */
function clearRedirectError(): void {
  const url = new URL(window.location.href);
  const hash = new URLSearchParams(url.hash.replace(/^#/, ""));
  for (const k of AUTH_ERROR_PARAMS) {
    url.searchParams.delete(k);
    hash.delete(k);
  }
  url.hash = hash.toString();
  window.history.replaceState(window.history.state, "", url.toString());
}

// Read and clear before the client below looks at the address.
export const redirectError: string | null = readRedirectError();
if (redirectError) clearRedirectError();

export const supabase: SupabaseClient | null =
  AUTH_MODE === "supabase"
    ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { flowType: "pkce", detectSessionInUrl: true, persistSession: true },
      })
    : null;
