// Your own APIs: add one (its spec linked or uploaded), prove you control it with a file on it,
// change its spec, remove it. Only approved APIs are offered in the scan form. The server checks
// every rule again, the proof before every scan, and the address on every scan connection.

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { API_MODE } from "../api/config";
import { MAX_SPEC_BYTES, precheckSpec, precheckTarget, ScanRefused, targets as targetService } from "../api/service";
import type { NewTarget, OwnTarget, SpecSource, TargetList } from "../api/types";
import { useSession } from "../auth/session";
import { plural } from "../lib/format";
import { FuzzText } from "../components/FuzzText";

type Field = ScanRefused["field"];
type FormError = { message: string; field?: Field } | null;

const asError = (err: unknown, fallback: string): FormError =>
  err instanceof ScanRefused
    ? { message: err.message, field: err.field }
    : { message: err instanceof Error && err.message ? err.message : fallback };

// ---- the spec: a link, or a file ----------------------------------------------------------------

interface SpecDraft {
  mode: "link" | "upload";
  url: string;
  file: { name: string; text: string } | null;
}

const draftToSource = (d: SpecDraft): SpecSource =>
  d.mode === "upload" && d.file ? { spec: d.file } : { specUrl: d.mode === "link" ? d.url : "" };

function SpecInput({
  idPrefix,
  draft,
  onChange,
  error,
  disabled,
}: {
  idPrefix: string;
  draft: SpecDraft;
  onChange: (d: SpecDraft, touchedUrl?: boolean) => void;
  error: FormError;
  disabled: boolean;
}) {
  const [reading, setReading] = useState(false);
  const fieldError = error && (error.field === "specUrl" || error.field === "spec") ? error : null;
  const errorId = `${idPrefix}-spec-error`;

  async function pick(file: File | undefined) {
    if (!file) return onChange({ ...draft, file: null });
    if (file.size > MAX_SPEC_BYTES * 4) {
      // Far too big to be worth reading; the exact limit is checked on the text below.
      return onChange({ ...draft, file: { name: file.name, text: "x".repeat(MAX_SPEC_BYTES + 1) } });
    }
    setReading(true);
    try {
      onChange({ ...draft, file: { name: file.name, text: await file.text() } });
    } finally {
      setReading(false);
    }
  }

  return (
    <fieldset className="spec-input" disabled={disabled || reading}>
      <legend className="field__label">OpenAPI spec</legend>
      <div className="spec-input__modes">
        {(["link", "upload"] as const).map((mode) => (
          <label className="spec-input__mode" key={mode}>
            <input
              type="radio"
              name={`${idPrefix}-spec-mode`}
              checked={draft.mode === mode}
              onChange={() => onChange({ ...draft, mode })}
            />
            {mode === "link" ? "Link to it" : "Upload a file"}
          </label>
        ))}
      </div>
      {draft.mode === "link" ? (
        <>
          <input
            key="link" // a different element from the file picker, not the same one changing type
            id={`${idPrefix}-spec`}
            aria-label="Spec address"
            className="input input--mono"
            inputMode="url"
            spellCheck={false}
            value={draft.url}
            onChange={(e) => onChange({ ...draft, url: e.target.value }, true)}
            aria-invalid={fieldError ? true : undefined}
            aria-describedby={[`${idPrefix}-spec-hint`, fieldError ? errorId : ""].filter(Boolean).join(" ")}
          />
          <span className="field__hint" id={`${idPrefix}-spec-hint`}>
            On the API's own address, as one document: references to other files or URLs aren't followed.
          </span>
        </>
      ) : (
        <>
          <input
            key="file"
            id={`${idPrefix}-spec-file`}
            aria-label="Spec file"
            className="input spec-input__file"
            type="file"
            accept=".json,.yaml,.yml,application/json,application/yaml,text/yaml"
            onChange={(e) => pick(e.target.files?.[0])}
            aria-invalid={fieldError ? true : undefined}
            aria-describedby={[`${idPrefix}-file-hint`, fieldError ? errorId : ""].filter(Boolean).join(" ")}
          />
          <span className="field__hint" id={`${idPrefix}-file-hint`}>
            {reading
              ? "Reading the file…"
              : draft.file
                ? `${draft.file.name} is ready to send.`
                : "JSON or YAML, up to 1 MB, as one document. For APIs that don't publish their spec. It's kept with the API until you change or remove it."}
          </span>
        </>
      )}
      {fieldError && (
        <p className="field__error" id={errorId} role="alert">
          {fieldError.message}
        </p>
      )}
    </fieldset>
  );
}

// ---- one API in the list ------------------------------------------------------------------------

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
  return <span className="api-status api-status--pending">Not proven yet</span>;
}

function CopyLine({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="proof__line">
      <code>{text}</code>
      <button
        type="button"
        className="link-button"
        onClick={() =>
          navigator.clipboard
            ?.writeText(text)
            .then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            })
            .catch(() => undefined)
        }
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

function ApiItem({ t, token, onChanged }: { t: OwnTarget; token: string; onChanged: (t?: OwnTarget) => void }) {
  const [confirming, setConfirming] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<SpecDraft>({ mode: t.specUrl ? "link" : "upload", url: t.specUrl ?? "", file: null });
  const [specError, setSpecError] = useState<FormError>(null);
  const [saving, setSaving] = useState(false);

  async function check() {
    setChecking(true);
    setCheckError(null);
    try {
      onChanged(await targetService.verify(t.id, token));
    } catch (err) {
      setCheckError(asError(err, "The check didn't run. Try again in a minute.")?.message ?? null);
    } finally {
      setChecking(false);
    }
  }

  async function saveSpec(e: FormEvent) {
    e.preventDefault();
    const src = draftToSource(draft);
    const refused = precheckSpec(src, t.url);
    if (refused) return setSpecError({ message: refused.message, field: refused.field });
    setSaving(true);
    setSpecError(null);
    try {
      onChanged(await targetService.replaceSpec(t.id, src, token));
      setEditing(false);
    } catch (err) {
      setSpecError(asError(err, "The spec wasn't changed. Try again in a minute."));
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    setConfirming(false);
    try {
      await targetService.remove(t.id, token);
      onChanged();
    } catch (err) {
      setCheckError(asError(err, "The API wasn't removed. Try again in a minute.")?.message ?? null);
    }
  }

  return (
    <li className="api-list__item">
      <div className="api-list__main">
        <span className="api-list__name">{t.label}</span>
        <code className="api-list__url">{t.url.replace(/^https:\/\//, "")}</code>
        <span className="api-list__spec">
          Spec: {t.specName ? `${t.specName} (uploaded)` : <code>{(t.specUrl ?? "").replace(t.url, "") || "/"}</code>}
          {!editing && (
            <>
              {" "}
              <button type="button" className="link-button" onClick={() => setEditing(true)}>
                Change
              </button>
            </>
          )}
        </span>
        {t.note && <span className="api-list__note">Note from the site's operator: {t.note}</span>}
      </div>
      <Status t={t} />
      <div className="api-list__actions">
        {t.status === "approved" && (t.scansLeftToday ?? 1) > 0 && (
          <Link className="button button--quiet" to="/" state={{ target: t.id }}>
            Scan it
          </Link>
        )}
        {confirming ? (
          <span className="api-list__confirm">
            Remove {t.label}?{" "}
            <button type="button" className="link-button" onClick={remove}>
              Remove
            </button>{" "}
            <button type="button" className="link-button" onClick={() => setConfirming(false)}>
              Keep
            </button>
          </span>
        ) : (
          <button type="button" className="link-button" onClick={() => setConfirming(true)}>
            Remove
          </button>
        )}
      </div>

      {editing && (
        <form className="api-list__panel api-form api-form--inline" onSubmit={saveSpec} noValidate>
          <SpecInput
            idPrefix={`edit-${t.id}`}
            draft={draft}
            onChange={(d) => {
              setDraft(d);
              setSpecError(null);
            }}
            error={specError}
            disabled={saving}
          />
          {specError && !specError.field && (
            <p className="notice notice--error" role="alert">
              {specError.message}
            </p>
          )}
          <div className="api-form__buttons">
            <button className="button" type="submit" disabled={saving}>
              {saving ? "Saving…" : "Save spec"}
            </button>
            <button type="button" className="link-button" onClick={() => setEditing(false)} disabled={saving}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {t.status === "pending" && t.proof && (
        <div className="api-list__panel proof">
          <p className="proof__title">Prove that you control {t.label}</p>
          <ol className="proof__steps">
            <li>
              Publish a plain text file at <code className="proof__url">{t.proof.url}</code>
            </li>
            <li>
              Put this line in it (other lines are fine): <CopyLine text={t.proof.line} />
            </li>
            <li>
              <button type="button" className="button button--quiet" onClick={check} disabled={checking}>
                {checking ? "Checking…" : "Check now"}
              </button>
            </li>
          </ol>
          <p className="field__hint">
            The file must be served at exactly that address, over HTTPS, without a redirect. It's checked again before
            every scan, so removing it later withdraws your permission.
          </p>
        </div>
      )}
      {t.status === "approved" && t.verifiedAt && t.proof && (
        <p className="api-list__panel field__hint">
          Proven by the file at <code>{t.proof.url}</code>. Keep it there: it's checked before every scan.
        </p>
      )}
      {checkError && (
        <p className="api-list__panel notice notice--error" role="alert">
          {checkError}
        </p>
      )}
    </li>
  );
}

// ---- the page -----------------------------------------------------------------------------------

const EMPTY = { label: "", url: "", authorized: false };
const EMPTY_SPEC: SpecDraft = { mode: "link", url: "", file: null };

export function YourApis() {
  const { session } = useSession();
  const token = session?.accessToken ?? "";
  const [list, setList] = useState<TargetList | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [form, setForm] = useState(EMPTY);
  const [spec, setSpec] = useState<SpecDraft>(EMPTY_SPEC);
  const [specTouched, setSpecTouched] = useState(false);
  const [error, setError] = useState<FormError>(null);
  const [busy, setBusy] = useState(false);
  const [added, setAdded] = useState<string | null>(null);

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

  function update<K extends keyof typeof EMPTY>(key: K, value: (typeof EMPTY)[K]) {
    setForm((f) => ({ ...f, [key]: value }));
    // Suggest the usual spec address beside the API until the user types their own.
    if (key === "url" && !specTouched) {
      const base = String(value).trim().replace(/\/+$/, "");
      setSpec((s) => ({ ...s, url: base ? `${base}/openapi.json` : "" }));
    }
    if (error && (error.field === key || (key === "url" && error.field === "specUrl"))) setError(null);
    setAdded(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const target = { ...form, ...draftToSource(spec) } as NewTarget;
    const refused = precheckTarget(target);
    if (refused) return setError({ message: refused.message, field: refused.field });
    setError(null);
    setBusy(true);
    try {
      const t = await targetService.add(target, token);
      setAdded(
        t.status === "approved"
          ? `${t.label} was added and is approved, so you can scan it now.`
          : `${t.label} was added. Prove that you control it (the steps are in the list above), and you can scan it.`,
      );
      setForm(EMPTY);
      setSpec(EMPTY_SPEC);
      setSpecTouched(false);
      load();
    } catch (err) {
      setError(asError(err, "The API wasn't added. Try again in a minute."));
    } finally {
      setBusy(false);
    }
  }

  function changed(t?: OwnTarget) {
    if (t && list) setList({ ...list, targets: list.targets.map((x) => (x.id === t.id ? t : x)) });
    else load();
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
        Add an API you own or have written permission to test, then prove that you control it by publishing a short
        file on it. Once that's found, you can scan it.
      </p>
      {API_MODE === "mock" && (
        <p className="field__hint">Preview build: APIs are kept in this browser, and Check now approves them at once.</p>
      )}

      <ul className="api-rules">
        <li>Served over HTTPS, on port 443 or 8443, at an address on the public internet.</li>
        <li>
          Its OpenAPI spec is on the same address, so the server can download it under the same rules, or you upload
          the file.
        </li>
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
            <ApiItem key={t.id} t={t} token={token} onChanged={changed} />
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
          <SpecInput
            idPrefix="api"
            draft={spec}
            onChange={(d, touchedUrl) => {
              setSpec(d);
              if (touchedUrl) setSpecTouched(true);
              if (error?.field === "specUrl" || error?.field === "spec") setError(null);
              setAdded(null);
            }}
            error={error}
            disabled={busy}
          />
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
