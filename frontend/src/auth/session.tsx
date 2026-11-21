// Sign-in state. With a Supabase project configured (VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY),
// sign-in goes through Supabase: Google OAuth, or e-mail and password. Without one it is simulated,
// so the UI can be worked on. Pages see the same shape either way.
//
// There is no sign-up. Who may sign in is decided outside the browser: turn off new sign-ups in
// Supabase (so a Google account that isn't already a user is refused), and have the backend check
// the e-mail in the access token. Nothing here can enforce it.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Session as SupabaseSession } from "@supabase/supabase-js";
import { AUTH_MODE } from "../api/config";
import { redirectError, supabase } from "./supabase";

export interface Session {
  email: string;
  provider: "google" | "email";
  accessToken: string; // sent to the backend, which verifies it with Supabase
}

interface SessionApi {
  session: Session | null;
  ready: boolean; // false until a session left over from an earlier visit (or a redirect) is known
  notice: string | null; // why the last sign-in redirect was refused, if it was
  signInWithGoogle(): Promise<void>;
  signInWithPassword(email: string, password: string): Promise<void>;
  /** Finish a Google sign-in with Google's ID token (from our backend's code exchange). */
  signInWithGoogleToken(idToken: string): Promise<void>;
  signOut(): Promise<void>;
}

const MOCK_KEY = "apifuzz-web:session";
const NOT_SET_UP = "Sign-in isn't set up on this deployment yet.";
const SessionContext = createContext<SessionApi | null>(null);

function fromSupabase(s: SupabaseSession | null): Session | null {
  if (!s) return null;
  return {
    email: s.user.email ?? "",
    provider: s.user.app_metadata?.provider === "google" ? "google" : "email",
    accessToken: s.access_token,
  };
}

function loadMock(): Session | null {
  try {
    const raw = sessionStorage.getItem(MOCK_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

function saveMock(s: Session | null): void {
  try {
    if (s) sessionStorage.setItem(MOCK_KEY, JSON.stringify(s));
    else sessionStorage.removeItem(MOCK_KEY);
  } catch {
    // storage blocked: the session lasts until the tab reloads
  }
}

/** Supabase's own wording for a refused sign-in, rewritten to say what to do. */
function explain(message: string): string {
  if (/signups? not allowed/i.test(message)) {
    return "New accounts can't be created right now. If you already have one, sign in with it.";
  }
  if (/invalid login credentials/i.test(message)) return "That e-mail address and password don't match.";
  return message;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => (supabase ? null : loadMock()));
  const [ready, setReady] = useState(!supabase);
  const [notice, setNotice] = useState<string | null>(redirectError);

  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data, error }) => {
      if (error) setNotice(explain(error.message));
      setSession(fromSupabase(data.session));
      setReady(true);
    });
    const { data } = supabase.auth.onAuthStateChange((_event, s) => setSession(fromSupabase(s)));
    return () => data.subscription.unsubscribe();
  }, []);

  const signInWithGoogle = useCallback(async () => {
    setNotice(null);
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (!supabase) {
      const next: Session = { email: "owner@example.com", provider: "google", accessToken: "mock-token" };
      saveMock(next);
      setSession(next);
      return;
    }
    // Leaves the page for Google, then comes back here; the client finishes the sign-in on return.
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: { redirectTo: window.location.origin + "/" },
    });
    if (error) throw new Error(explain(error.message));
  }, []);

  const signInWithGoogleToken = useCallback(async (idToken: string) => {
    setNotice(null);
    if (!supabase) throw new Error(NOT_SET_UP);
    const { error } = await supabase.auth.signInWithIdToken({ provider: "google", token: idToken });
    if (error) throw new Error(explain(error.message));
  }, []);

  const signInWithPassword = useCallback(async (email: string, password: string) => {
    setNotice(null);
    if (!email.includes("@") || password.length === 0) throw new Error("Enter your e-mail address and password.");
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (!supabase) {
      const next: Session = { email, provider: "email", accessToken: "mock-token" };
      saveMock(next);
      setSession(next);
      return;
    }
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw new Error(explain(error.message));
  }, []);

  // Always ends signed out in this tab, even if Supabase can't be reached to end the session there.
  const signOut = useCallback(async () => {
    try {
      if (supabase) await supabase.auth.signOut();
      else saveMock(null);
    } catch {
      if (supabase) await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
    } finally {
      setSession(null);
    }
  }, []);

  const value = useMemo(
    () => ({ session, ready, notice, signInWithGoogle, signInWithGoogleToken, signInWithPassword, signOut }),
    [session, ready, notice, signInWithGoogle, signInWithGoogleToken, signInWithPassword, signOut],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionApi {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside <SessionProvider>");
  return ctx;
}

export const authIsSimulated = AUTH_MODE === "mock";
