// Who sent each piece of evidence, and what it was for. Each check stores its exchanges in a
// fixed order (see the `evidence=[...]` lines in src/apifuzz/checks/*.py), so the role can be read
// from the position. Only BOLA knows which account sent a request; elsewhere the UI says only
// whether a credential was attached.

import type { Exchange, Finding } from "../api/types";

export type Actor = "a" | "b" | "token" | "none";

export interface Role {
  label: string;
  actor: Actor;
}

const CREDENTIAL_HEADERS = ["authorization", "cookie", "x-api-key"];

export function hasCredential(ex: Exchange): boolean {
  return Object.entries(ex.request.headers).some(
    ([k, v]) => CREDENTIAL_HEADERS.includes(k.toLowerCase()) || v === "[redacted]",
  );
}

function labels(f: Finding): string[] {
  switch (f.check) {
    case "bola":
      return ["Account A", "Account B", "No token", "Account B, again"];
    case "auth-required":
      return ["No token", "No token, again"];
    case "mass-assignment":
      return f.endpoint.startsWith("POST ")
        ? ["Create with the extra field", "Read it back", "Delete the test object"]
        : ["Update with the extra field", "Read it back", "Put the old value back"];
    case "rate-limit":
      return ["First request of the burst", "Last request of the burst"];
    case "injection":
      if (f.detail.includes("one extra quote")) return ["Plain value", "Same value with one extra quote"];
      if (f.detail.includes("always-true")) return ["Always-true value", "Always-false value"];
      if (f.detail.includes("operator object")) return ["Plain value", "Operator object instead of a value"];
      return [];
    default:
      return [];
  }
}

export function rolesFor(f: Finding): Role[] {
  const named = labels(f);
  return f.evidence.map((ex, i) => {
    const label = named[i] ?? `Request ${i + 1}`;
    let actor: Actor = hasCredential(ex) ? "token" : "none";
    if (f.check === "bola") actor = (["a", "b", "none", "b"] as Actor[])[i] ?? actor;
    return { label, actor };
  });
}

/** Index of an earlier exchange whose response body is identical, or -1. */
export function sameBodyAs(evidence: Exchange[], i: number): number {
  const body = evidence[i]?.response?.body;
  if (body === undefined) return -1;
  for (let j = 0; j < i; j++) if (evidence[j].response?.body === body) return j;
  return -1;
}

export function prettyBody(body: string | null | undefined): string {
  if (!body) return "";
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

/** The path and query of a URL, which is what a reader needs; the host is the scan target. */
export function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return decodeURI(u.pathname) + decodeURIComponent(u.search);
  } catch {
    return url;
  }
}
