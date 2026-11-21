import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { CHECKS } from "../api/checks";
import { ALLOWLIST, API_MODE, DEMO_TARGET, LIMITS } from "../api/config";
import { precheck, ScanRefused, scans } from "../api/service";
import type { CheckId } from "../api/types";
import { useSession } from "../auth/session";
import { plural } from "../lib/format";
import { Mark } from "../components/Mark";
import { RequestTicker } from "../components/RequestTicker";
import { FuzzText } from "../components/FuzzText";

type Field = ScanRefused["field"];

export function NewScan() {
  const { session } = useSession();
  const navigate = useNavigate();
  const [target, setTarget] = useState(DEMO_TARGET);
  const [specUrl, setSpecUrl] = useState(`${DEMO_TARGET}/openapi.json`);
  const [specTouched, setSpecTouched] = useState(false);
  const [checks, setChecks] = useState<CheckId[]>(CHECKS.map((c) => c.id));
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<{ message: string; field?: Field } | null>(null);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [left, setLeft] = useState<number | null>(null);

  const token = session?.accessToken ?? "";

  useEffect(() => {
    scans.scansLeftToday(token).then(setLeft);
  }, [token]);

  useEffect(() => {
    if (!running) return;
    const start = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 250);
    return () => clearInterval(id);
  }, [running]);

  function chooseTarget(value: string) {
    setTarget(value);
    // Keep the spec beside the target until the user types their own spec address.
    if (!specTouched) setSpecUrl(`${value.replace(/\/+$/, "")}/openapi.json`);
    if (error?.field === "target" || error?.field === "specUrl") setError(null);
  }

  function toggle(id: CheckId) {
    setChecks((cur) => (cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]));
    if (error?.field === "checks") setError(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const req = { target: target.trim(), specUrl: specUrl.trim(), checks, authorized };
    const refused = precheck(req);
    if (refused) {
      setError({ message: refused.message, field: refused.field });
      return;
    }
    setError(null);
    setElapsed(0);
    setRunning(true);
    try {
      const record = await scans.startScan(req, token);
      navigate(`/scans/${record.id}`);
    } catch (err) {
      setError(
        err instanceof ScanRefused
          ? { message: err.message, field: err.field }
          : { message: "The scan didn't start: the server gave no answer. Try again in a minute." },
      );
      setRunning(false);
    }
  }

  const errorFor = (field: Field) =>
    error && error.field === field ? (
      <p className="field__error" id={`${field}-error`} role="alert">
        {error.message}
      </p>
    ) : null;
  const invalid = (field: Field) => (error?.field === field ? true : undefined);
  const describedBy = (field: Field, hint?: string) =>
    [hint, error?.field === field ? `${field}-error` : undefined].filter(Boolean).join(" ") || undefined;
  const noneLeft = left === 0;

  return (
    <>
      <h1 className="page-title">
        <FuzzText text="Scan an API" />
      </h1>
      <p className="lede">
        The server reads the API's OpenAPI spec, runs the checks you pick, and shows what it found with the requests
        that prove it.
      </p>

      <form className="scan-form" onSubmit={submit} noValidate>
        <div className="scan-form__row">
          <label className="field__label" htmlFor="target">
            Target
          </label>
          <div className="field">
            <input
              id="target"
              className="input input--mono"
              value={target}
              inputMode="url"
              spellCheck={false}
              onChange={(e) => chooseTarget(e.target.value)}
              aria-invalid={invalid("target")}
              aria-describedby={describedBy("target", "target-hint")}
              disabled={running}
            />
            <div className="allowlist" id="target-hint">
              <span className="field__hint">This server only scans:</span>
              {ALLOWLIST.map((a) => (
                <button
                  key={a.host}
                  type="button"
                  className="allowlist__item"
                  onClick={() => chooseTarget(`${new URL(DEMO_TARGET).protocol}//${a.host}`)}
                  disabled={running}
                >
                  {a.label} <code>{a.host}</code>
                </button>
              ))}
            </div>
            {errorFor("target")}
          </div>
        </div>

        <div className="scan-form__row">
          <label className="field__label" htmlFor="spec">
            OpenAPI spec
          </label>
          <div className="field">
            <input
              id="spec"
              className="input input--mono"
              value={specUrl}
              inputMode="url"
              spellCheck={false}
              onChange={(e) => {
                setSpecUrl(e.target.value);
                setSpecTouched(true);
                if (error?.field === "specUrl") setError(null);
              }}
              aria-invalid={invalid("specUrl")}
              aria-describedby={describedBy("specUrl", "spec-hint")}
              disabled={running}
            />
            <span className="field__hint" id="spec-hint">
              The server downloads the spec itself, so it has to be on an allowed host too.
            </span>
            {errorFor("specUrl")}
          </div>
        </div>

        <div className="scan-form__row" role="group" aria-labelledby="checks-label" aria-describedby={describedBy("checks")}>
          <span className="field__label scan-form__group-label" id="checks-label">
            Checks
          </span>
          <div className="field">
            <div className="checklist">
              {CHECKS.map((c) => (
                <label className="checklist__item" key={c.id}>
                  <input
                    type="checkbox"
                    checked={checks.includes(c.id)}
                    onChange={() => toggle(c.id)}
                    disabled={running}
                  />
                  <span>
                    <span className="checklist__name">{c.name}</span>
                    <span className="checklist__owasp">{c.owasp.split(" ")[0]}</span>
                    <span className="checklist__summary">{c.summary}</span>
                  </span>
                </label>
              ))}
            </div>
            {errorFor("checks")}
          </div>
        </div>

        <div className="field">
          <label className="consent">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => {
                setAuthorized(e.target.checked);
                if (error?.field === "authorized") setError(null);
              }}
              aria-invalid={invalid("authorized")}
              aria-describedby={describedBy("authorized")}
              disabled={running}
            />
            <span className="consent__text">
              I own this target or have written permission to test it.
              <span className="consent__sub">
                The same confirmation as the CLI's --i-have-authorization flag. Every scan is logged with your account.
              </span>
            </span>
          </label>
          {errorFor("authorized")}
        </div>

        <div className="scan-form__submit">
          {running ? (
            <div className="running">
              <p className="running__status" role="status">
                <Mark className="running__mark" />
                Scanning {target.replace(/^https?:\/\//, "")}, {plural(elapsed, "second")} so far
              </p>
              {API_MODE === "mock" && <RequestTicker checks={checks} />}
            </div>
          ) : (
            <button className="button" type="submit" disabled={noneLeft}>
              Start scan
            </button>
          )}
          {left !== null && !running && (
            <span className="scan-form__limits">
              {noneLeft
                ? "You've used all of today's scans. The count resets at midnight."
                : `${plural(left, "scan")} left today. Rate-limit bursts are capped at ${LIMITS.burst} requests.`}
            </span>
          )}
        </div>
        {error && (!error.field || error.field === "limit") && (
          <p className="notice notice--error" role="alert">
            {error.message}
          </p>
        )}
      </form>
    </>
  );
}
