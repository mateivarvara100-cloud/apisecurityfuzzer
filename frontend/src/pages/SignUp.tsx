// Create an account: with Google (the account is made on the first sign-in), or with e-mail and a
// password, confirmed by a link e-mailed to that address. The answer after "Create account" is the
// same whether or not the address already has an account, so the page can't be used to find out.

import { useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router-dom";
import { severityLabel } from "../api/checks";
import { SAMPLE_REPORT } from "../api/service";
import { authIsSimulated, useSession } from "../auth/session";
import { useCaptcha } from "../components/Captcha";
import { FuzzText } from "../components/FuzzText";
import { GoogleSignIn } from "../components/GoogleSignIn";
import { MIN_PASSWORD } from "./ResetPassword";

type FieldName = "email" | "password" | "repeat" | "agree";

// The right-hand column: what an account is for, shown with the real scan of the lab.
function LabFindings() {
  const r = SAMPLE_REPORT;
  return (
    <aside className="signin__aside" aria-labelledby="lab-findings-title">
      <h2 className="signin__aside-title" id="lab-findings-title">
        What a scan of the lab finds
      </h2>
      <p className="signin__aside-text">
        A real scan of the VulnShop lab: {r.requests_sent} requests to {r.endpoints_scanned} endpoints, and these{" "}
        {r.findings.length} findings, worst first. Your account keeps reports like this for 30 days.
      </p>
      <ol className="lab-findings">
        {r.findings.map((f) => (
          <li key={f.fingerprint} className="lab-findings__item">
            <span className={`sev sev--${f.severity}`}>{severityLabel(f.severity)}</span>
            <span className="lab-findings__endpoint">{f.endpoint}</span>
            <span className="lab-findings__title">{f.title}</span>
          </li>
        ))}
      </ol>
      <p className="lab-findings__more">
        <Link to="/sample">Open the full report, with the requests that prove each one</Link>
      </p>
    </aside>
  );
}

export function SignUp() {
  const { session, ready, signUp } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [agree, setAgree] = useState(false);
  const [busy, setBusy] = useState(false);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [error, setError] = useState<{ message: string; field: FieldName | null } | null>(null);
  const captcha = useCaptcha("sign_up");

  if (!ready) return null;
  if (session) return <Navigate to="/" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    const address = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
      return setError({ message: "Enter a valid e-mail address.", field: "email" });
    }
    if (password.length < MIN_PASSWORD) {
      return setError({ message: `Use at least ${MIN_PASSWORD} characters.`, field: "password" });
    }
    if (password !== repeat) return setError({ message: "The two passwords don't match.", field: "repeat" });
    if (!agree) return setError({ message: "Agree to the terms of use to create an account.", field: "agree" });
    setError(null);
    setBusy(true);
    try {
      const outcome = await signUp(address, password, await captcha.token());
      if (outcome === "confirm") setSentTo(address); // signed in at once otherwise; the page redirects
    } catch (err) {
      captcha.reset(); // the token is spent either way; the next try needs a new one
      setError({ message: err instanceof Error ? err.message : "The account wasn't created. Try again.", field: null });
    } finally {
      setBusy(false);
    }
  }

  const invalid = (field: FieldName) => (error?.field === field ? true : undefined);
  const errorFor = (field: FieldName | null) =>
    error && error.field === field ? (
      <p className="field__error" id={`signup-${field ?? "form"}-error`} role="alert">
        {error.message}
      </p>
    ) : null;

  if (sentTo) {
    return (
      <div className="signin">
        <div className="signup">
          <h1 className="page-title">
            <FuzzText text="Check your inbox" />
          </h1>
          <p className="lede" role="status">
            If {sentTo} can be used for a new account, a link to confirm it is on its way. Open it in this browser to
            finish. If nothing arrives in a few minutes, look in spam, or <Link to="/">sign in</Link> if you already have
            an account.
          </p>
        </div>
        <LabFindings />
      </div>
    );
  }

  return (
    <div className="signin">
      <div className="signup">
        <h1 className="page-title">
          <FuzzText text="Create an account" />
        </h1>
        <p className="lede">Scan the VulnShop lab and keep your reports for 30 days.</p>

        <div className="signin__google">
          <GoogleSignIn signUp />
          <span className="field__hint signin__agree">
            With Google, the account is made when you first continue. By continuing you agree to the{" "}
            <Link to="/terms">terms of use</Link> and confirm you've read the <Link to="/privacy">privacy notice</Link>.
          </span>
        </div>

        <p className="signin__or">
          <span>or with e-mail</span>
        </p>

        <form className="signin__form" onSubmit={submit} noValidate>
          <div className="field">
            <label className="field__label" htmlFor="signup-email">
              E-mail address
            </label>
            <input
              id="signup-email"
              className="input"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-invalid={invalid("email")}
            />
            {errorFor("email")}
          </div>
          <div className="field">
            <label className="field__label" htmlFor="signup-password">
              Password
            </label>
            <input
              id="signup-password"
              className="input"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-invalid={invalid("password")}
              aria-describedby="signup-password-hint"
            />
            <span className="field__hint" id="signup-password-hint">
              At least {MIN_PASSWORD} characters. A few unrelated words make a strong one.
            </span>
            {errorFor("password")}
          </div>
          <div className="field">
            <label className="field__label" htmlFor="signup-repeat">
              The same password again
            </label>
            <input
              id="signup-repeat"
              className="input"
              type="password"
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => setRepeat(e.target.value)}
              aria-invalid={invalid("repeat")}
            />
            {errorFor("repeat")}
          </div>
          <label className="signup__agree">
            <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} aria-invalid={invalid("agree")} />
            <span>
              I agree to the <Link to="/terms">terms of use</Link> and have read the <Link to="/privacy">privacy notice</Link>.
            </span>
          </label>
          {errorFor("agree")}
          {authIsSimulated && <span className="field__hint">Preview build: the account is made at once, nothing is sent.</span>}
          {errorFor(null)}
          <div>
            {captcha.box}
            <button className="button" type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create account"}
            </button>
          </div>
        </form>
        <p className="signup__switch">
          Already have an account? <Link to="/">Sign in</Link>
        </p>
      </div>
      <LabFindings />
    </div>
  );
}
