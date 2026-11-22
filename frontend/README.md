# apifuzz web

The front end of the hosted demo, live at <https://apifuzz.vercel.app>. A signed-in user picks
a target (the VulnShop lab, or one of their own APIs once an admin approves it), picks the checks,
confirms they are allowed to test it, starts a scan, and reads the same findings the CLI produces. It never runs checks itself: the backend
([../backend](../backend)) runs the apifuzz engine and returns its JSON report.

React 19 + TypeScript, built with Vite, styled with SCSS. Deployed on Vercel.

```sh
cd frontend
npm install
cp .env.example .env.local   # then fill it in; .env.local is git-ignored
npm run dev                  # http://localhost:5173
npm run build                # type-check, then build into dist/
npm run preview              # the built app, with the production security headers
```

## Settings

All of them are `VITE_` variables, so they end up in the public page: never put a secret here.
Locally they go in `.env.local`; on Vercel under Settings -> Environment Variables (type
Config), and a change needs a redeploy because Vite builds them in.
[.env.example](.env.example) explains each one.

| Variable | What it is |
| --- | --- |
| `VITE_API_MODE` | `live` calls the backend; `mock` answers from the bundled sample scan (for UI work) |
| `VITE_API_URL` | The backend, e.g. `https://apifuzz-api.onrender.com` (locally `http://127.0.0.1:8001`) |
| `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY` | The Supabase project (public values). Without them sign-in is simulated in `npm run dev` |
| `VITE_GOOGLE_CLIENT_ID` | Google's OAuth web client id, for the Google button |
| `VITE_TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key, for the bot check on the e-mail forms |
| `VITE_OPERATOR_NAME`, `VITE_CONTACT_EMAIL` | Who runs the site, shown in the terms and privacy notice |

## Sign-in

- **Google.** apifuzz's own button opens Google's window (Google Identity Services, code flow).
  Google returns a one-time code, the backend exchanges it for Google's ID token (it holds the
  client secret), and Supabase signs in with that token, so Google's screen names apifuzz. If
  Google's script can't load, the button falls back to Supabase's redirect. On the sign-up page
  a Google account that already has an account is refused ("sign in instead").
- **E-mail and password.** Sign-up needs a 10+ character password and a confirmation link sent
  by e-mail. "Forgot your password?" e-mails a reset link. Both say the same thing whether or not
  the address has an account. An account created with Google has no password and can't get one.
- **Bot check.** The e-mail sign-in, sign-up and reset forms send Supabase a Cloudflare Turnstile
  token (`src/components/Captcha.tsx`). It is invisible unless Cloudflare needs an answer.
  Google sign-in doesn't use it.

Each outside address (Supabase's redirect URLs, Google's JavaScript origins, Turnstile's
hostnames) must list the site's address. The setup is in [../backend/README.md](../backend/README.md).

## Security

- [vercel.json](vercel.json) sets the headers: a strict Content Security Policy (scripts only
  from the site, Google's sign-in script and Cloudflare's check; connections only to Supabase and
  the backend), no framing, HSTS, and a Cross-Origin-Opener-Policy that still allows Google's
  window. `npm run preview` sends the same headers, so the built app can be checked locally.
- Fonts are self-hosted (`@fontsource`), and the build keeps them as files so the policy can
  stay `font-src 'self'`. Nothing is loaded for tracking.
- The browser checks the allowlist only to explain a refusal early. The backend enforces it.

## Layout

| Path | What it holds |
| --- | --- |
| `src/api/` | Report types (mirroring `report.py`), the check list, settings, and the scan service (live or mock) |
| `src/auth/` | Sign-in state, the Supabase client, Google's code flow, and the Turnstile loader |
| `src/components/` | Layout, the report view, a finding, the evidence timeline, the Google button, the bot check, the storage notice |
| `src/pages/` | Sign in, sign up, reset password, new scan, your APIs, history, scan report, sample report, terms and privacy |
| `src/lib/` | Evidence ordering, formatting, motion helpers |
| `src/styles/` | SCSS partials: tokens, mixins, base, chrome, forms, report, evidence, legal, motion |

## Design notes

- Black, white and red, the same family as the HTML report's dark theme. Account A (the owner)
  is white and account B (the one who got an object that isn't theirs) is red wherever they
  appear; requests with no token are grey. The token swap is the core of the BOLA check, and the
  evidence timeline is built around it.
- The mono face (Martian Mono) is used only for HTTP content: endpoints, requests and bodies.
  The UI text is Schibsted Grotesk.
- Severity is written in sentence case and paired with a mark, so it doesn't depend on color
  alone. Every text color pair passes WCAG AA.
