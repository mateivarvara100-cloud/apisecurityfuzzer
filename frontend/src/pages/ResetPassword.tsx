// Password reset, in two halves on one page.
// Not signed in: ask for a reset link by e-mail. The answer is the same whether or not an account
// exists, so the page can't be used to find out who has one.
// Signed in (which is what the e-mail's link does): choose a new password.

import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { authIsSimulated, GOOGLE_ONLY, useSession } from "../auth/session";
import { FuzzText } from "../components/FuzzText";

export const MIN_PASSWORD = 10;

export function ResetPassword() {
  const { session, ready } = useSession();
  if (!ready) return null;
  return session ? <ChooseNewPassword /> : <RequestLink />;
}

function RequestLink() {
  // `notice`: why a reset link that brought someone here didn't work (expired, already used).
  const { requestPasswordReset, notice } = useSession();
  const location = useLocation();
  const [email, setEmail] = useState(() => (location.state as { email?: string } | null)?.email ?? "");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError("Enter the e-mail address you sign in with.");
      return;
    }
    setBusy(true);
    try {
      await requestPasswordReset(email.trim());
      setSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The link couldn't be sent. Try again in a minute.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="reset">
      <h1 className="page-title">
        <FuzzText text="Reset your password" />
      </h1>
      {sent ? (
        <>
          <p className="lede" role="status">
            If an account exists for {email.trim()}, a link to choose a new password is on its way. It works once and
            expires after an hour.
          </p>
          {authIsSimulated && <p className="field__hint">Preview build: no e-mail is sent.</p>}
          <p className="reset__back">
            <Link to="/">Back to sign in</Link>
          </p>
        </>
      ) : (
        <>
          <p className="lede">Enter the address you sign in with, and we'll e-mail you a link to choose a new one.</p>
          {notice && (
            <p className="notice notice--error reset__notice" role="alert">
              {notice}
            </p>
          )}
          <form className="reset__form" onSubmit={submit} noValidate>
            <div className="field">
              <label className="field__label" htmlFor="reset-email">
                E-mail address
              </label>
              <input
                id="reset-email"
                className="input"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                aria-invalid={error ? true : undefined}
                aria-describedby={error ? "reset-error" : undefined}
              />
            </div>
            {error && (
              <p className="field__error" id="reset-error" role="alert">
                {error}
              </p>
            )}
            <div>
              <button className="button" type="submit" disabled={busy}>
                {busy ? "Sending…" : "Send reset link"}
              </button>
            </div>
          </form>
          <p className="reset__back">
            <Link to="/">Back to sign in</Link>
          </p>
        </>
      )}
    </div>
  );
}

function ChooseNewPassword() {
  const { session } = useSession();
  if (session && !session.canHavePassword) {
    return (
      <div className="reset">
        <h1 className="page-title">
          <FuzzText text="No password to change" />
        </h1>
        <p className="lede">{GOOGLE_ONLY}</p>
        <p className="field__hint">To change your Google password, go to your Google Account, under Security.</p>
        <p className="reset__back">
          <Link to="/">Go to the start page</Link>
        </p>
      </div>
    );
  }
  return <NewPasswordForm />;
}

function NewPasswordForm() {
  const { session, updatePassword } = useSession();
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ message: string; field: "password" | "repeat" | null } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (password.length < MIN_PASSWORD) {
      setError({ message: `Use at least ${MIN_PASSWORD} characters.`, field: "password" });
      return;
    }
    if (password !== repeat) {
      setError({ message: "The two passwords don't match.", field: "repeat" });
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await updatePassword(password);
      navigate("/", { replace: true, state: { passwordChanged: true } });
    } catch (err) {
      setError({ message: err instanceof Error ? err.message : "The password wasn't changed. Try again.", field: null });
      setBusy(false);
    }
  }

  const invalid = (field: "password" | "repeat") => (error?.field === field ? true : undefined);

  return (
    <div className="reset">
      <h1 className="page-title">
        <FuzzText text="Choose a new password" />
      </h1>
      <p className="lede">For {session?.email}. You'll stay signed in.</p>
      <form className="reset__form" onSubmit={submit} noValidate>
        <div className="field">
          <label className="field__label" htmlFor="new-password">
            New password
          </label>
          <input
            id="new-password"
            className="input"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-invalid={invalid("password")}
            aria-describedby="new-password-hint"
          />
          <span className="field__hint" id="new-password-hint">
            At least {MIN_PASSWORD} characters. A few unrelated words make a strong one.
          </span>
        </div>
        <div className="field">
          <label className="field__label" htmlFor="repeat-password">
            The same password again
          </label>
          <input
            id="repeat-password"
            className="input"
            type="password"
            autoComplete="new-password"
            value={repeat}
            onChange={(e) => setRepeat(e.target.value)}
            aria-invalid={invalid("repeat")}
          />
        </div>
        {error && (
          <p className="field__error" role="alert">
            {error.message}
          </p>
        )}
        <div>
          <button className="button" type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save new password"}
          </button>
        </div>
      </form>
    </div>
  );
}
