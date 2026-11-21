import type { CheckId, Severity } from "./types";

/** What each check looks for, in the words the report uses. Order = the order shown in the form. */
export const CHECKS: { id: CheckId; name: string; owasp: string; summary: string }[] = [
  {
    id: "bola",
    name: "Object-level authorization",
    owasp: "API1:2023 Broken Object Level Authorization",
    summary: "Logs in as two test accounts and asks for one account's objects with the other's token.",
  },
  {
    id: "auth-required",
    name: "Missing authentication",
    owasp: "API2:2023 Broken Authentication",
    summary: "Calls endpoints that need a login without a token, and checks they refuse.",
  },
  {
    id: "mass-assignment",
    name: "Mass assignment",
    owasp: "API3:2023 Broken Object Property Level Authorization",
    summary: "Adds one field the spec doesn't allow to an update, reads it back, then restores it.",
  },
  {
    id: "rate-limit",
    name: "Missing rate limit",
    owasp: "API4:2023 Unrestricted Resource Consumption",
    summary: "Sends a short, capped burst to login and search endpoints and looks for throttling.",
  },
  {
    id: "injection",
    name: "SQL and NoSQL injection",
    owasp: "API8:2019 Injection",
    summary: "Sends harmless marker values and compares response shape. Reads no records.",
  },
];

export const checkName = (id: string): string => CHECKS.find((c) => c.id === id)?.name ?? id;

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/** Sentence case for display; the report itself keeps the upper-case values. */
export const severityLabel = (s: Severity): string => s.charAt(0) + s.slice(1).toLowerCase();
