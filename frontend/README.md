# apifuzz web (Phase 4)

The front end of the hosted demo: a signed-in user picks an allowlisted target, confirms they are
authorized, starts a scan, and reads the same findings the CLI produces. It never runs checks
itself; the backend runs the apifuzz engine and returns its JSON report.

React 19 + TypeScript, built with Vite, styled with SCSS. Meant for Vercel (`vercel.json` sends
every path to the single page).

```sh
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173
npm run build      # type-check, then build into dist/
```

## Status

Only the UI exists. `VITE_API_MODE=mock` (the default) answers from
`src/data/sample-scan.json`, a redacted scan of the VulnShop lab, and keeps history in the
browser. Still to build: the FastAPI backend, scan storage in Supabase, and the live
`ScanService` in `src/api/service.ts`.

The browser checks the allowlist only to explain a refusal early. The server must enforce it, for
the target and for the spec download.

## Sign-in (Google, or e-mail and password)

Sign-in goes through Supabase Auth once `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` are set
in `.env.local`. Without them it is simulated: both buttons sign you in at once.

To turn on Google:

1. In Google Cloud Console, create an OAuth client of type "Web application". Add Supabase's
   callback as an authorized redirect URI: `https://<project-ref>.supabase.co/auth/v1/callback`.
2. In Supabase, go to Authentication, then Sign In / Providers, then Google. Paste the client ID
   and secret there. The secret stays in Supabase and never goes in this app.
3. In Supabase, under Authentication, then URL Configuration, set the Site URL to the deployed app.
   Add `http://127.0.0.1:5173/` to the redirect URLs for local work.
4. Keep sign-in limited to the owner, as the plan says. Sign in once with your own Google
   account, then turn off "Allow new users to sign up" in Supabase. Any other Google account is
   then refused, and the sign-in page explains why. The backend should also check the e-mail in
   the access token, because nothing in the browser can enforce who signs in.

## Layout

| Path | What it holds |
| --- | --- |
| `src/api/` | Report types (mirroring `report.py`), the check list, config, and the `ScanService` |
| `src/auth/` | The Supabase client and sign-in state (Google, e-mail and password, or simulated) |
| `src/lib/evidence.ts` | Which request in a finding was sent by whom, read from each check's fixed evidence order |
| `src/components/` | Layout, the report view, a finding, and the evidence timeline |
| `src/pages/` | Sign in, new scan, scan report, history, public sample report |
| `src/styles/` | SCSS partials: tokens, mixins, base, chrome, forms, report, evidence |

## Design notes

- Account A is indigo and account B is teal everywhere they appear. Requests with no token get a
  hollow grey badge. The token swap is the core of the BOLA check, and the evidence timeline is
  built around it.
- The mono face (Martian Mono) is used only for HTTP content: endpoints, requests and bodies.
  The UI text is Schibsted Grotesk.
- Severity is written in sentence case and paired with a colored square, so it doesn't depend on
  color alone.
