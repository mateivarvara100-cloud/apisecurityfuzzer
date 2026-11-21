// A one-time note about what the site stores, with a link to the details. Everything it stores is
// needed for the site to work (staying signed in), so this informs rather than asks for consent.

import { useState } from "react";
import { Link } from "react-router-dom";

const KEY = "apifuzz-web:notice";

function seen(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function StorageNotice() {
  const [open, setOpen] = useState(() => !seen());
  if (!open) return null;

  const close = () => {
    try {
      localStorage.setItem(KEY, "1");
    } catch {
      // storage blocked: the note comes back next visit
    }
    setOpen(false);
  };

  return (
    <aside className="storage-notice" aria-label="Browser storage">
      <p className="storage-notice__text">
        This site keeps your sign-in in your browser's storage. No tracking cookies, no analytics.{" "}
        <Link to="/privacy#cookies">What's stored</Link>
      </p>
      <button type="button" className="button button--quiet storage-notice__close" onClick={close}>
        OK
      </button>
    </aside>
  );
}
