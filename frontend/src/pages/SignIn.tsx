import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { SAMPLE_REPORT } from "../api/service";
import { authIsSimulated, useSession } from "../auth/session";
import { Evidence } from "../components/Evidence";
import { GoogleButton } from "../components/GoogleButton";
import { FuzzText } from "../components/FuzzText";

// The planted BOLA flaw, as the scanner recorded it: the first two requests are the token swap.
const bola = SAMPLE_REPORT.findings.find((f) => f.check === "bola");
const swap = bola && { ...bola, evidence: bola.evidence.slice(0, 2) };

const failed = (err: unknown) => (err instanceof Error ? err.message : "Sign-in failed. Try again.");

export function SignIn() {
  const { signInWithGoogle, signInWithPassword, notice } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [googleError, setGoogleError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"google" | "password" | null>(null);

  async function google() {
    setBusy("google");
    setGoogleError(null);
    try {
      await signInWithGoogle(); // on success the page goes to Google, so busy stays set
      if (authIsSimulated) setBusy(null);
    } catch (err) {
      setGoogleError(failed(err));
      setBusy(null);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy("password");
    setError(null);
    try {
      await signInWithPassword(email.trim(), password);
    } catch (err) {
      setError(failed(err));
    } finally {
      setBusy(null);
    }
  }

  const refused = googleError ?? notice;

  return (
    <div className="signin">
      <div>
        <h1 className="page-title">
          <FuzzText text="Sign in to run a scan" />
        </h1>
        <p className="lede">
          Scans run on this server against the VulnShop lab only. Sign-in is limited to the project owner for now.
        </p>
        <div className="signin__google">
          <GoogleButton onClick={google} busy={busy === "google"} />
          {refused && (
            <p className="notice notice--error" role="alert">
              {refused}
            </p>
          )}
          {authIsSimulated && (
            <span className="field__hint">Preview build: no Supabase project is set up, so this signs you in at once.</span>
          )}
        </div>

        <p className="signin__or">
          <span>or with e-mail</span>
        </p>

        <form className="signin__form" onSubmit={submit} noValidate>
          <div className="field">
            <label className="field__label" htmlFor="email">
              E-mail address
            </label>
            <input
              id="email"
              className="input"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? "signin-error" : undefined}
            />
          </div>
          <div className="field">
            <label className="field__label" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              className="input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? "signin-error" : undefined}
            />
            {authIsSimulated && (
              <span className="field__hint">Preview build: any e-mail address and password will do.</span>
            )}
          </div>
          {error && (
            <p className="field__error" id="signin-error" role="alert">
              {error}
            </p>
          )}
          <div>
            <button className="button" type="submit" disabled={busy !== null}>
              {busy === "password" ? "Signing in…" : "Sign in with e-mail"}
            </button>
          </div>
        </form>
      </div>

      {swap && (
        <aside className="signin__aside" aria-labelledby="swap-title">
          <h2 className="signin__aside-title" id="swap-title">
            One order, two accounts, the same answer
          </h2>
          <p className="signin__aside-text">
            apifuzz asks for account A's order with account B's token. A safe API refuses; this one handed it over. These
            are the two requests from a real scan of the lab. <Link to="/sample">See the full sample report</Link>.
          </p>
          <Evidence finding={swap} />
        </aside>
      )}
    </div>
  );
}
