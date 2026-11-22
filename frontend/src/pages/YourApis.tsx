// Your own APIs: add one, see whether an admin has approved it, remove it. Only approved APIs are
// offered in the scan form. The server checks every rule again, and on every scan connection.

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { API_MODE } from "../api/config";
import { precheckTarget, ScanRefused, targets as targetService } from "../api/service";
import type { NewTarget, OwnTarget, TargetList } from "../api/types";
import { useSession } from "../auth/session";
import { plural } from "../lib/format";
import { FuzzText } from "../components/FuzzText";

type Field = ScanRefused["field"];

const EMPTY: NewTarget = { label: "", url: "", specUrl: "", authorized: false };

function Status({ t }: { t: OwnTarget }) {
  if (t.status === "approved") {
    return (
      <span className="api-status api-status--approved">
        Approved
        {t.scansLeftToday !== undefined && (
          <span className="api-status__sub">
            {t.scansLeftToday === 0 ? "No scans left today" : `${plural(t.scansLeftToday, "scan")} left today`}
          </span>
        )}
      </span>
    );
  }
  if (t.status === "rejected") return <span className="api-status api-status--rejected">Not approved</span>;
  return <span className="api-status api-status--pending">Waiting for approval</span>;
}

export function YourApis() {
  const { session } = useSession();
  const token = session?.accessToken ?? "";
  const [list, setList] = useState<TargetList | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [form, setForm] = useState<NewTarget>(EMPTY);
  const [specTouched, setSpecTouched] = useState(false);
  const [error, setError] = useState<{ message: string; field?: Field } | null>(null);
  const [busy, setBusy] = useState(false);
  const [added, setAdded] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = useCallback(() => {
    targetService
      .list(token)
      .then((l) => {
        setList(l);
        setLoadError(null);
      })
      .catch((err: Error) => setLoadError(err.message));
  }, [token]);

  useEffect(load, [load]);

  function update<K extends keyof NewTarget>(key: K, value: NewTarget[K]) {
    setForm((f) => {
      const next = { ...f, [key]: value };
      // Suggest the usual spec address beside the API until the user types their own.
      if (key === "url" && !specTouched) {
        const base = String(value).trim().replace(/\/+$/, "");
        next.specUrl = base ? `${base}/openapi.json` : "";
      }
      return next;
    });
    if (key === "specUrl") setSpecTouched(true);
    if (error && (error.field === key || (key === "url" && error.field === "specUrl"))) setError(null);
    setAdded(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const refused = precheckTarget(form);
    if (refused) return setError({ message: refused.message, field: refused.field });
    setError(null);
    setBusy(true);
    try {
      const t = await targetService.add(form, token);
      setAdded(`${t.label} was added. ${t.status === "approved" ? "It's approved, so you can scan it now." : "It's waiting for approval."}`);
      setForm(EMPTY);
      setSpecTouched(false);
      load();
    } catch (err) {
      setError(
        err instanceof ScanRefused
          ? { message: err.message, field: err.field }
          : { message: err instanceof Error ? err.message : "The API wasn't added. Try again in a minute." },
      );
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setConfirming(null);
    try {
      await targetService.remove(id, token);
      load();
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "The API wasn't removed. Try again in a minute.");
    }
  }

  const errorFor = (field: Field) =>
    error && error.field === field ? (
      <p className="field__error" id={`api-${field}-error`} role="alert">
        {error.message}
      </p>
    ) : null;
  const invalid = (field: Field) => (error?.field === field ? true : undefined);
  const describedBy = (field: Field, hint?: string) =>
    [hint, error?.field === field ? `api-${field}-error` : undefined].filter(Boolean).join(" ") || undefined;
  const full = !!list && list.targets.length >= list.maxTargets;

  return (
    <>
      <h1 className="page-title">
        <FuzzText text="Your APIs" />
      </h1>
      <p className="lede">
        Add an API you own or have written permission to test. An admin checks each one by hand before it can be
        scanned, and you'll see its status change here.
      </p>
      {API_MODE === "mock" && (
        <p className="field__hint">Preview build: APIs are kept in this browser and approved at once.</p>
      )}

      <ul className="api-rules">
        <li>Served over HTTPS, on port 443 or 8443, at an address on the public internet.</li>
        <li>Its OpenAPI spec is on the same address, so the server can download it under the same rules.</li>
        <li>
          Up to {list?.maxTargets ?? 3} APIs per account, each scanned at most {list?.scansPerTargetPerDay ?? 3} times a
          day. Scans count towards your daily scans too.
        </li>
        <li>Scan a staging copy, not production: the checks send probes, swap test accounts' tokens and change test data.</li>
      </ul>

      {loadError && (
        <p className="notice notice--error" role="alert">
          {loadError}
        </p>
      )}

      {list && list.targets.length > 0 && (
        <ul className="api-list" aria-label="Your APIs">
          {list.targets.map((t) => (
            <li className="api-list__item" key={t.id}>
              <div className="api-list__main">
                <span className="api-list__name">{t.label}</span>
                <code className="api-list__url">{t.url.replace(/^https:\/\//, "")}</code>
                {t.note && <span className="api-list__note">Note from the admin: {t.note}</span>}
              </div>
              <Status t={t} />
              <div className="api-list__actions">
                {t.status === "approved" && (t.scansLeftToday ?? 1) > 0 && (
                  <Link className="button button--quiet" to="/" state={{ target: t.id }}>
                    Scan it
                  </Link>
                )}
                {confirming === t.id ? (
                  <span className="api-list__confirm">
                    Remove {t.label}?{" "}
                    <button type="button" className="link-button" onClick={() => remove(t.id)}>
                      Remove
                    </button>{" "}
                    <button type="button" className="link-button" onClick={() => setConfirming(null)}>
                      Keep
                    </button>
                  </span>
                ) : (
                  <button type="button" className="link-button" onClick={() => setConfirming(t.id)}>
                    Remove
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      <h2 className="section-title">Add an API</h2>
      {full ? (
        <p className="field__hint">You have {list?.maxTargets} APIs, the most an account can have. Remove one to add another.</p>
      ) : (
        <form className="api-form" onSubmit={submit} noValidate>
          <div className="field">
            <label className="field__label" htmlFor="api-label">
              Name
            </label>
            <input
              id="api-label"
              className="input"
              value={form.label}
              maxLength={60}
              onChange={(e) => update("label", e.target.value)}
              aria-invalid={invalid("label")}
              aria-describedby={describedBy("label")}
              disabled={busy}
            />
            {errorFor("label")}
          </div>
          <div className="field">
            <label className="field__label" htmlFor="api-url">
              API address
            </label>
            <input
              id="api-url"
              className="input input--mono"
              inputMode="url"
              spellCheck={false}
              placeholder="https://staging-api.example.com"
              value={form.url}
              onChange={(e) => update("url", e.target.value)}
              aria-invalid={invalid("url")}
              aria-describedby={describedBy("url")}
              disabled={busy}
            />
            {errorFor("url")}
          </div>
          <div className="field">
            <label className="field__label" htmlFor="api-spec">
              OpenAPI spec
            </label>
            <input
              id="api-spec"
              className="input input--mono"
              inputMode="url"
              spellCheck={false}
              value={form.specUrl}
              onChange={(e) => update("specUrl", e.target.value)}
              aria-invalid={invalid("specUrl")}
              aria-describedby={describedBy("specUrl", "api-spec-hint")}
              disabled={busy}
            />
            <span className="field__hint" id="api-spec-hint">
              One document: references to other files or URLs aren't followed.
            </span>
            {errorFor("specUrl")}
          </div>
          <label className="consent">
            <input
              type="checkbox"
              checked={form.authorized}
              onChange={(e) => update("authorized", e.target.checked)}
              aria-invalid={invalid("authorized")}
              aria-describedby={describedBy("authorized")}
              disabled={busy}
            />
            <span className="consent__text">
              I own this API or have written permission to test it.
              <span className="consent__sub">
                You're responsible for the scans you start. See the <Link to="/terms">terms of use</Link>.
              </span>
            </span>
          </label>
          {errorFor("authorized")}
          {error && (!error.field || error.field === "limit") && (
            <p className="notice notice--error" role="alert">
              {error.message}
            </p>
          )}
          {added && (
            <p className="notice notice--ok" role="status">
              {added}
            </p>
          )}
          <div>
            <button className="button" type="submit" disabled={busy}>
              {busy ? "Adding…" : "Add API"}
            </button>
          </div>
        </form>
      )}
    </>
  );
}
