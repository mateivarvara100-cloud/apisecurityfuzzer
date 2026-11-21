// Sign-in state. With a Supabase project configured (VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY),
// sign-in goes through Supabase: Google OAuth, or e-mail and password. Without one it is simulated,
// so the UI can be worked on. Pages see the same shape either way.
//
// There is no sign-up. Who may sign in is decided outside the browser: turn off new sign-ups in
// Supabase (so a Google account that isn't already a user is refused), and have the backend check
// the e-mail in the access token. Nothing here can enforce it.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Session as SupabaseSession } from "@supabase/supabase-js";
import { AUTH_MODE } from "../api/config";
import { redirectError, supabase } from "./supabase";

export interface Session {
  email: string;
  provider: "google" | "email";
  // False for an account created with Google: it signs in only through Google and never gets a
  // password here (so "Forgot your password?" can't add a second way in).
  canHavePassword: boolean;
  accessToken: string; // sent to the backend, which verifies it with Supabase
}

interface SessionApi {
  session: Session | null;
  ready: boolean; // false until a session left over from an earlier visit (or a redirect) is known
  notice: string | null; // why the last sign-in redirect was refused, if it was
  signInWithGoogle(): Promise<void>;
  signInWithPassword(email: string, password: string): Promise<void>;
  /**
   * Create an e-mail account. "confirm": a confirmation link was e-mailed (the usual case; also
   * the answer when the address is taken, so nobody can find out who has an account).
   * "signed-in": the project doesn't ask for confirmation, and the account is ready.
   */
  signUp(email: string, password: string): Promise<"confirm" | "signed-in">;
  /** E-mail a link to choose a new password. Succeeds whether or not the account exists. */
  requestPasswordReset(email: string): Promise<void>;
  /** Set a new password for the signed-in account (after following the reset link). */
  updatePassword(password: string): Promise<void>;
  /**
   * Finish a Google sign-in with Google's ID token (from our backend's code exchange).
   * `newAccountOnly` (the sign-up page): refuse, and end this sign-in, if the account already existed.
   */
  signInWithGoogleToken(idToken: string, newAccountOnly?: boolean): Promise<void>;
  signOut(): Promise<void>;
}

const MOCK_KEY = "apifuzz-web:session";
const NOT_SET_UP = "Sign-in isn't set up on this deployment yet.";
const SessionContext = createContext<SessionApi | null>(null);

export const ALREADY_REGISTERED = "This Google account already has an apifuzz account. Sign in instead.";

/**
 * Did this sign-in just create the account? For a new account Supabase stamps the creation and the
 * sign-in in the same request; an older account was created earlier. Both times come from
 * Supabase, so the visitor's clock doesn't matter.
 */
function justCreated(user: SupabaseSession["user"]): boolean {
  const created = Date.parse(user.created_at);
  const signedIn = Date.parse(user.last_sign_in_at ?? user.created_at);
  return Number.isFinite(created) && Number.isFinite(signedIn) && signedIn - created < 60_000;
}

export const GOOGLE_ONLY = "This account signs in with Google, so it has no password here. Keep using Continue with Google.";

/** Does the account have an e-mail sign-in (not only Google)? */
function hasEmailSignIn(s: SupabaseSession): boolean {
  const providers: unknown = s.user.app_metadata?.providers;
  if (Array.isArray(providers)) return providers.includes("email");
  return s.user.app_metadata?.provider === "email";
}

function fromSupabase(s: SupabaseSession | null): Session | null {
  if (!s) return null;
  return {
    email: s.user.email ?? "",
    provider: s.user.app_metadata?.provider === "google" ? "google" : "email",
    canHavePassword: hasEmailSignIn(s),
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
  if (/rate limit|you can only request this after/i.test(message)) {
    return "Too many e-mails were asked for just now. Wait a minute, then try again.";
  }
  if (/different from the old password/i.test(message)) return "Choose a password you haven't used here before.";
  if (/already registered|already been registered/i.test(message)) {
    return "There's already an account for that address. Sign in, or use Forgot your password?.";
  }
  if (/email not confirmed/i.test(message)) {
    return "Confirm your e-mail address first: open the link we sent when you created the account.";
  }
  return message;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => (supabase ? null : loadMock()));
  const [ready, setReady] = useState(!supabase);
  const [notice, setNotice] = useState<string | null>(redirectError);
  // While a sign-up checks whether the Google account is new, sign-in events are held back, so the
  // page doesn't jump to the start page for an account that is about to be refused.
  const holdEvents = useRef(false);

  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data, error }) => {
      if (error) setNotice(explain(error.message));
      setSession(fromSupabase(data.session));
      setReady(true);
    });
    const { data } = supabase.auth.onAuthStateChange((_event, s) => {
      if (!holdEvents.current) setSession(fromSupabase(s));
    });
    return () => data.subscription.unsubscribe();
  }, []);

  const signInWithGoogle = useCallback(async () => {
    setNotice(null);
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (!supabase) {
      const next: Session = { email: "owner@example.com", provider: "google", canHavePassword: false, accessToken: "mock-token" };
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

  const signInWithGoogleToken = useCallback(async (idToken: string, newAccountOnly = false) => {
    setNotice(null);
    if (!supabase) throw new Error(NOT_SET_UP);
    holdEvents.current = newAccountOnly;
    try {
      const { data, error } = await supabase.auth.signInWithIdToken({ provider: "google", token: idToken });
      if (error) throw new Error(explain(error.message));
      if (newAccountOnly && data.user && !justCreated(data.user)) {
        // End only this sign-in (other devices stay signed in), then say why.
        await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
        setSession(null);
        throw new Error(ALREADY_REGISTERED);
      }
      if (newAccountOnly) setSession(fromSupabase(data.session));
    } finally {
      holdEvents.current = false;
    }
  }, []);

  const signUp = useCallback(async (email: string, password: string): Promise<"confirm" | "signed-in"> => {
    setNotice(null);
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (!supabase) {
      const next: Session = { email, provider: "email", canHavePassword: true, accessToken: "mock-token" };
      saveMock(next);
      setSession(next);
      return "signed-in";
    }
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: window.location.origin + "/" },
    });
    if (error) throw new Error(explain(error.message));
    return data.session ? "signed-in" : "confirm";
  }, []);

  const requestPasswordReset = useCallback(async (email: string) => {
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (!supabase) return; // preview: nothing is sent
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: window.location.origin + "/reset-password",
    });
    if (error) throw new Error(explain(error.message));
  }, []);

  const updatePassword = useCallback(async (password: string) => {
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (session && !session.canHavePassword) throw new Error(GOOGLE_ONLY);
    if (!supabase) return;
    const { error } = await supabase.auth.updateUser({ password });
    if (error) throw new Error(explain(error.message));
  }, [session]);

  const signInWithPassword = useCallback(async (email: string, password: string) => {
    setNotice(null);
    if (!email.includes("@") || password.length === 0) throw new Error("Enter your e-mail address and password.");
    if (AUTH_MODE === "off") throw new Error(NOT_SET_UP);
    if (!supabase) {
      const next: Session = { email, provider: "email", canHavePassword: true, accessToken: "mock-token" };
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
    () => ({
      session, ready, notice, signInWithGoogle, signInWithGoogleToken, signInWithPassword, signOut,
      requestPasswordReset, updatePassword, signUp,
    }),
    [session, ready, notice, signInWithGoogle, signInWithGoogleToken, signInWithPassword, signOut,
      requestPasswordReset, updatePassword, signUp],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionApi {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside <SessionProvider>");
  return ctx;
}

export const authIsSimulated = AUTH_MODE === "mock";
