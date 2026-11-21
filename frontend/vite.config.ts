import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The security headers live in vercel.json, which Vercel applies in production. `vite preview`
// sends the same ones, so the built app can be checked against the real policy locally. The dev
// server doesn't: its hot reload needs inline scripts that the policy forbids.
const vercel = JSON.parse(readFileSync(new URL("./vercel.json", import.meta.url), "utf8")) as {
  headers: { source: string; headers: { key: string; value: string }[] }[];
};
const securityHeaders = Object.fromEntries(
  vercel.headers.flatMap((rule) => rule.headers.map((h) => [h.key, h.value] as const)),
);

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, host: "127.0.0.1" },
  preview: { port: 4173, host: "127.0.0.1", headers: securityHeaders },
  // Vite inlines small files as data: URLs. Fonts stay files, so the policy can keep
  // `font-src 'self'` instead of also allowing data:.
  build: { assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined) },
});
