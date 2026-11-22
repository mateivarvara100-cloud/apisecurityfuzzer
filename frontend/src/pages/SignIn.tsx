import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { SAMPLE_REPORT } from "../api/service";
import { authIsSimulated, useSession } from "../auth/session";
import { useCaptcha } from "../components/Captcha";
import { Evidence } from "../components/Evidence";
import { GoogleSignIn } from "../components/GoogleSignIn";
import { FuzzText } from "../components/FuzzText";

// The planted BOLA flaw, as the scanner recorded it: the first two requests are the token swap.
const bola = SAMPLE_REPORT.findings.find((f) => f.check === "bola");
const swap = bola && { ...bola, evidence: bola.evidence.slice(0, 2) };

const failed = (err: unknown) => (err instanceof Error ? err.message : "Sign-in failed. Try again.");

export function SignIn() {
  const { signInWithPassword, notice } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const captcha = useCaptcha("sign_in");

  async function submit(e: FormEvent) {
    e.preventDefault();
    // checked here too, so an empty form doesn't spend a bot-check token
    if (!email.includes("@") || password.length === 0) return setError("Enter your e-mail address and password.");
    setBusy(true);
    setError(null);
    try {
      await signInWithPassword(email.trim(), password, await captcha.token());
    } catch (err) {
      captcha.reset(); // the token is spent either way; the next try needs a new one
      setError(failed(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="signin">
      <div>
        <h1 className="page-title">
          <FuzzText text="Sign in to run a scan" />
        </h1>
        <p className="lede">
          Sign in with Google or e-mail to scan the VulnShop lab, a deliberately vulnerable demo API, and keep your
          reports for 30 days.
        </p>
        <div className="signin__google">
          <GoogleSignIn notice={notice} />
          <span className="field__hint signin__agree">
            By continuing you agree to the <Link to="/terms">terms of use</Link> and confirm you've read the{" "}
            <Link to="/privacy">privacy notice</Link>.
          </span>
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
            <Link className="signin__forgot" to="/reset-password" state={{ email: email.trim() }}>
              Forgot your password?
            </Link>
          </div>
          {error && (
            <p className="field__error" id="signin-error" role="alert">
              {error}
            </p>
          )}
          <div>
            {captcha.box}
            <button className="button" type="submit" disabled={busy}>
              {busy ? "Signing in…" : "Sign in with e-mail"}
            </button>
          </div>
        </form>
        <p className="signup__switch">
          No account yet? <Link to="/sign-up">Create one</Link>
        </p>
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
