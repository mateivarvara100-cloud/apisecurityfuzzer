// Google sign-in from apifuzz's own button, without the Supabase address on Google's screen.
//
// Google Identity Services (code flow, in a popup) opens Google's window straight from our button.
// Google answers with a one-time code; our backend, which holds the client secret, trades it for
// Google's ID token (POST /auth/google), and Supabase signs in with that token
// (signInWithIdToken). Nothing redirects through <project>.supabase.co.
//
// Google's script is loaded only on the sign-in and sign-up pages, so the click can open Google's window at
// once (a browser only allows a popup straight from a click). No other page contacts Google.

import { API_URL } from "../api/config";

const SCRIPT = "https://accounts.google.com/gsi/client";

interface CodeResponse {
  code?: string;
  state?: string;
  error?: string;
}

export interface CodeClient {
  requestCode(): void;
}

interface GoogleOAuth2 {
  initCodeClient(config: {
    client_id: string;
    scope: string;
    ux_mode: "popup";
    state: string;
    select_account: boolean;
    callback: (response: CodeResponse) => void;
    error_callback: (error: { type?: string }) => void;
  }): CodeClient;
}

declare global {
  interface Window {
    google?: { accounts?: { oauth2?: GoogleOAuth2 } };
  }
}

let loading: Promise<GoogleOAuth2> | null = null;

export function loadGoogle(): Promise<GoogleOAuth2> {
  loading ??= new Promise<GoogleOAuth2>((resolve, reject) => {
    const ready = () => window.google?.accounts?.oauth2;
    if (ready()) return resolve(ready()!);
    const script = document.createElement("script");
    script.src = SCRIPT;
    script.async = true;
    const fail = () => {
      loading = null; // a later visit to the page can try again
      script.remove();
      reject(new Error("Google's sign-in didn't load."));
    };
    const timer = window.setTimeout(fail, 10_000);
    script.onload = () => {
      window.clearTimeout(timer);
      const oauth2 = ready();
      if (oauth2) resolve(oauth2);
      else fail();
    };
    script.onerror = () => {
      window.clearTimeout(timer);
      fail();
    };
    document.head.appendChild(script);
  });
  return loading;
}

/** A random value for this page, sent to Google and expected back, so a forged answer is ignored. */
export function randomState(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
}

export interface GoogleHandlers {
  onCode(code: string): void;
  onCancel(): void;
  onError(message: string): void;
}

/** Ready to open Google's window; call `requestCode()` from the click itself. */
export function codeClient(oauth2: GoogleOAuth2, clientId: string, handlers: GoogleHandlers): CodeClient {
  const state = randomState();
  return oauth2.initCodeClient({
    client_id: clientId,
    scope: "openid email profile",
    ux_mode: "popup",
    state,
    select_account: true, // always show the account chooser, so another account can be picked
    callback: (response) => {
      if (response.state !== state) return handlers.onError("Google's answer didn't match this sign-in. Try again.");
      if (response.error || !response.code) {
        return response.error === "access_denied" ? handlers.onCancel() : handlers.onError("Google sign-in didn't finish. Try again.");
      }
      handlers.onCode(response.code);
    },
    error_callback: (error) => {
      if (error.type === "popup_closed") handlers.onCancel();
      else if (error.type === "popup_failed_to_open") handlers.onError("The browser blocked Google's window. Allow pop-ups for this site and try again.");
      else handlers.onError("Google sign-in didn't finish. Try again.");
    },
  });
}

/** Our backend trades Google's one-time code for Google's ID token. */
export async function idTokenFor(code: string): Promise<string> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/auth/google`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
  } catch {
    throw new Error("Can't reach the sign-in server. On free hosting it sleeps when idle; try again in a minute.");
  }
  const body = (await res.json().catch(() => null)) as { idToken?: unknown; detail?: unknown } | null;
  if (res.ok && typeof body?.idToken === "string") return body.idToken;
  throw new Error(typeof body?.detail === "string" ? body.detail : "Google sign-in didn't finish. Try again.");
}
