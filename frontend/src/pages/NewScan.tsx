import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { CHECKS } from "../api/checks";
import { LAB } from "../api/config";
import { precheck, ScanRefused, scans, targets as targetService, type Limits } from "../api/service";
import type { CheckId, OwnTarget } from "../api/types";
import { useSession } from "../auth/session";
import { plural } from "../lib/format";
import { FuzzText } from "../components/FuzzText";

type Field = ScanRefused["field"];

const LAB_ID = "lab";
const host = (url: string) => url.replace(/^https?:\/\//, "");

export function NewScan() {
  const { session } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [own, setOwn] = useState<OwnTarget[]>([]);
  const [selected, setSelected] = useState<string>(() => (location.state as { target?: string } | null)?.target ?? LAB_ID);
  // Every check but rate-limit is on until the user turns it off. Rate-limit (a burst of requests)
  // defaults to on for the lab and off for someone's own API, unless the user has chosen.
  const [picked, setPicked] = useState<CheckId[]>(CHECKS.map((c) => c.id).filter((id) => id !== "rate-limit"));
  const [rateChoice, setRateChoice] = useState<boolean | null>(null);
  const [tokenA, setTokenA] = useState("");
  const [tokenB, setTokenB] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<{ message: string; field?: Field } | null>(null);
  const [running, setRunning] = useState(false); // starting: the server answers at once
  const [limits, setLimits] = useState<Limits | null>(null);

  const token = session?.accessToken ?? "";
  const approved = useMemo(() => own.filter((t) => t.status === "approved"), [own]);
  const waiting = own.filter((t) => t.status === "pending").length;
  const chosen = approved.find((t) => t.id === selected) ?? null; // null: the lab
  const isOwn = chosen !== null;
  const rateOn = rateChoice ?? !isOwn;
  const checks = useMemo(
    () => CHECKS.map((c) => c.id).filter((id) => (id === "rate-limit" ? rateOn : picked.includes(id))),
    [picked, rateOn],
  );

  useEffect(() => {
    let current = true;
    scans
      .limits(token)
      .then((l) => current && setLimits(l))
      .catch((err: Error) => current && setError({ message: err.message }));
    targetService
      .list(token)
      .then((list) => current && setOwn(list.targets))
      .catch(() => undefined); // the lab can still be scanned; the APIs page shows the problem
    return () => {
      current = false;
    };
  }, [token]);

  // A target asked for (from the APIs page) that isn't approved, or doesn't exist: fall back to the lab.
  useEffect(() => {
    if (selected !== LAB_ID && own.length > 0 && !approved.some((t) => t.id === selected)) setSelected(LAB_ID);
  }, [own, approved, selected]);

  function choose(id: string) {
    setSelected(id);
    if (error?.field === "target" || error?.field === "specUrl" || error?.field === "limit") setError(null);
  }

  function toggle(id: CheckId) {
    if (id === "rate-limit") setRateChoice(!rateOn);
    else setPicked((cur) => (cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]));
    if (error?.field === "checks") setError(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const target = chosen ?? LAB;
    const req = {
      target: target.url,
      // A user's own API is scanned with the spec stored with it (a link, or an uploaded file).
      specUrl: target.specUrl ?? "",
      checks,
      authorized,
      ...(isOwn ? { tokenA: tokenA.trim() || undefined, tokenB: tokenB.trim() || undefined } : {}),
    };
    const refused = precheck(req, [LAB.url, ...approved.map((t) => t.url)]);
    if (refused) {
      setError({ message: refused.message, field: refused.field });
      return;
    }
    setError(null);
    setRunning(true);
    try {
      // The scan runs in the background; its page shows the progress, then the report.
      const job = await scans.startScan(req, token);
      navigate(`/scans/${job.id}`);
    } catch (err) {
      setError(
        err instanceof ScanRefused
          ? { message: err.message, field: err.field }
          : { message: err instanceof Error && err.message ? err.message : "The scan didn't start. Try again in a minute." },
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
  const noneLeft = limits?.left === 0;
  const targetSpent = chosen?.scansLeftToday === 0;
  const busy = limits?.running ?? null; // this account's scan that hasn't finished yet

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
        <div className="scan-form__row" role="radiogroup" aria-labelledby="target-label" aria-describedby={describedBy("target")}>
          <span className="field__label scan-form__group-label" id="target-label">
            Target
          </span>
          <div className="field">
            <div className="targets">
              <label className="targets__item">
                <input
                  type="radio"
                  name="target"
                  checked={!isOwn}
                  onChange={() => choose(LAB_ID)}
                  disabled={running}
                />
                <span>
                  <span className="targets__name">{LAB.label}</span>
                  <span className="targets__detail">
                    A deliberately vulnerable demo API that runs on the scan server itself, so nothing outside it is
                    contacted.
                  </span>
                </span>
              </label>
              {approved.map((t) => (
                <label className="targets__item" key={t.id}>
                  <input
                    type="radio"
                    name="target"
                    checked={selected === t.id}
                    onChange={() => choose(t.id)}
                    disabled={running}
                  />
                  <span>
                    <span className="targets__name">{t.label}</span>
                    <code className="targets__url">{host(t.url)}</code>
                    <span className="targets__detail">
                      Your API.{" "}
                      {t.scansLeftToday === undefined
                        ? ""
                        : t.scansLeftToday === 0
                          ? "Scanned as often as allowed today."
                          : `${plural(t.scansLeftToday, "scan")} of it left today.`}
                    </span>
                  </span>
                </label>
              ))}
            </div>
            <p className="field__hint targets__add">
              <Link to="/apis">{approved.length ? "Manage your APIs" : "Add your own API"}</Link>
              {waiting > 0 && ` · ${plural(waiting, "API")} waiting for approval`}
            </p>
            {errorFor("target")}
            {errorFor("specUrl")}
          </div>
        </div>

        {isOwn && (
          <div className="scan-form__row">
            <span className="field__label scan-form__group-label">Test accounts</span>
            <div className="field tokens">
              <p className="field__hint tokens__intro" id="tokens-hint">
                Bearer tokens of two different test accounts on your API, so apifuzz can check whether one can read the
                other's data. They're used for this scan only and never saved. Never use an admin's or a real user's
                token. Without them the account checks (BOLA, mass assignment) have nothing to test.
              </p>
              {(["A", "B"] as const).map((who) => {
                const field = who === "A" ? "tokenA" : "tokenB";
                const value = who === "A" ? tokenA : tokenB;
                return (
                  <div className="field" key={who}>
                    <label className="field__label" htmlFor={field}>
                      Account {who} token
                    </label>
                    <input
                      id={field}
                      className="input input--mono"
                      type="password"
                      autoComplete="off"
                      spellCheck={false}
                      value={value}
                      onChange={(e) => {
                        (who === "A" ? setTokenA : setTokenB)(e.target.value);
                        if (error?.field === field) setError(null);
                      }}
                      aria-invalid={invalid(field)}
                      aria-describedby={describedBy(field, "tokens-hint")}
                      disabled={running}
                    />
                    {errorFor(field)}
                  </div>
                );
              })}
            </div>
          </div>
        )}

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
            {isOwn && (
              <span className="field__hint">
                The rate-limit check sends a burst of up to {limits?.burst ?? 15} requests, so it starts switched off for
                your own API.
              </span>
            )}
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

        {busy && (
          <p className="notice" role="status">
            Your scan of {busy.label} is still running. <Link to={`/scans/${busy.id}`}>Watch its progress</Link>; you
            can start another once it's done.
          </p>
        )}
        <div className="scan-form__submit">
          <button className="button" type="submit" disabled={running || noneLeft || targetSpent || !!busy}>
            {running ? "Starting…" : "Start scan"}
          </button>
          {limits && !running && (
            <span className="scan-form__limits">
              {noneLeft
                ? "You've used all of today's scans. The count resets at midnight UTC."
                : `${limits.left === null ? "No daily limit on this account." : `${plural(limits.left, "scan")} left today.`} Rate-limit bursts are capped at ${limits.burst} requests.`}
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
