// "Continue with Google", used on the sign-in and the sign-up page (Google makes the account on the
// first visit). Our own button opens Google's window directly: Google answers with a one-time code,
// our backend trades it for Google's ID token, and Supabase signs in with that token, so Google's
// screen never shows the Supabase address. Without the backend or Google's script, the button
// falls back to Supabase's redirect.

import { useEffect, useRef, useState } from "react";
import { API_URL, AUTH_MODE, GOOGLE_CLIENT_ID } from "../api/config";
import { codeClient, idTokenFor, loadGoogle, type CodeClient } from "../auth/google";
import { authIsSimulated, useSession } from "../auth/session";
import { GoogleButton } from "./GoogleButton";

const GOOGLE_POPUP = AUTH_MODE === "supabase" && !!GOOGLE_CLIENT_ID && !!API_URL;

const failed = (err: unknown) => (err instanceof Error ? err.message : "Sign-in failed. Try again.");

/**
 * `notice`: a message from the page to show in the same place (e.g. a refused redirect).
 * `signUp`: on the sign-up page a Google account that already has an apifuzz account is refused
 * ("sign in instead") rather than signed in.
 */
export function GoogleSignIn({ notice, signUp = false }: { notice?: string | null; signUp?: boolean }) {
  const { signInWithGoogle, signInWithGoogleToken } = useSession();
  // "failed": Google's script couldn't load, or isn't configured; the button uses the redirect.
  const google = useRef<CodeClient | null>(null);
  const [gis, setGis] = useState<"loading" | "ready" | "failed">(GOOGLE_POPUP ? "loading" : "failed");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!GOOGLE_POPUP) return;
    let live = true;
    loadGoogle()
      .then((oauth2) => {
        if (!live) return;
        google.current = codeClient(oauth2, GOOGLE_CLIENT_ID, {
          onCode: (code) => {
            idTokenFor(code)
              .then((idToken) => signInWithGoogleToken(idToken, signUp))
              .catch((err) => setError(failed(err)))
              .finally(() => setBusy(false));
          },
          onCancel: () => setBusy(false),
          onError: (message) => {
            setError(message);
            setBusy(false);
          },
        });
        setGis("ready");
      })
      .catch(() => live && setGis("failed"));
    return () => {
      live = false;
    };
  }, [signInWithGoogleToken, signUp]);

  async function click() {
    setError(null);
    setBusy(true);
    if (gis === "ready" && google.current) {
      google.current.requestCode(); // must run inside the click, or the browser blocks Google's window
      return;
    }
    try {
      await signInWithGoogle(); // the Supabase redirect: the page goes to Google, so busy stays set
      if (authIsSimulated) setBusy(false);
    } catch (err) {
      setError(failed(err));
      setBusy(false);
    }
  }

  const shown = error ?? notice;
  return (
    <>
      <GoogleButton onClick={click} busy={busy} disabled={gis === "loading"} />
      {shown && (
        <p className="notice notice--error" role="alert">
          {shown}
        </p>
      )}
    </>
  );
}
