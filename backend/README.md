# apifuzz web backend

The server behind the hosted demo. It checks each visitor's Supabase sign-in, runs the apifuzz
engine (the package in the repository root) against the targets configured here and nowhere
else, and keeps scan history in Supabase.

## Run it locally

```
cd backend
uv sync
cp .env.example .env          # then fill it in; .env is git-ignored
uv run uvicorn apifuzz_web.main:app --host 127.0.0.1 --port 8001
uv run pytest                 # the tests
```

The lab target must be running too (see "Lab target" in the main README). Every setting is listed
in [.env.example](.env.example).

## Routes

| Route | What it does |
| --- | --- |
| `GET /health` | Is the server up (no sign-in; Render's health check) |
| `GET /me` | Who you are, scans left today, the lab, and your scan that is still running |
| `POST /scans` | Starts a scan in the background and answers `202` at once with its job |
| `GET /scans/{id}/progress` | Phase, current check, steps done, requests sent, the last 8 requests (paths only). Polled; it has its own rate limit |
| `POST /scans/{id}/cancel` | Stops the scan before its next step, so no check is cut off halfway; the partial report is kept |
| `GET /scans`, `GET /scans/{id}` | History, and one scan (its job while it runs) |
| `GET /targets`, `POST /targets` | Your APIs; add one with its spec linked (`specUrl`) or uploaded (`spec: {name, text}`, up to 1 MB) |
| `POST /targets/{id}/verify` | Looks for the proof file on the API and approves it if the file is there |
| `PUT /targets/{id}/spec` | Changes an API's spec (a new link or a new upload) |
| `DELETE /targets/{id}` | Removes one of your APIs |
| `POST /auth/google` | Trades Google's one-time sign-in code for its ID token |

Someone else's scan or API always answers 404, like one that doesn't exist. Scans run one at a
time on the whole server; jobs live in the server's memory, so a restart loses a running scan
(the web app then says so), while finished reports are in Supabase.

## Deploy it (Render)

[render.yaml](../render.yaml) describes one free web service. Its start command,
[start.sh](start.sh), runs the VulnShop lab inside the same service on `127.0.0.1:8000`, so the
scanner reaches it and the internet never does. The deliberately vulnerable lab must never get a
public address of its own.

- In Render: New -> Blueprint, pick this repository. Render asks for each secret listed in
  render.yaml (Supabase URL and secret key, Google client id and secret, the lab's two test
  accounts); take them from your `backend/.env`. They live only in Render.
- `ALLOWED_ORIGINS` in render.yaml is the frontend's address. Change it there if the site moves.
- Then set the frontend's `VITE_API_URL` (in Vercel) to the service's `https://...onrender.com`
  address and redeploy the frontend.
- A free service sleeps after 15 minutes without traffic and takes about a minute to wake, so the
  first request after a quiet spell is slow. A scan first waits for the lab's `/health`
  (`TARGET_WAKE_SECONDS`, default 30) so it doesn't fail while the lab is starting.

## What has to be set up outside this repository

**Supabase**
- Apply the migrations in [supabase/migrations](supabase/migrations), in order (SQL editor: paste
  each file and run it): the `scans` table and the server's grants on it, the rule that keeps
  passwords off Google accounts, the `targets` table for users' own APIs, and its proof and
  upload columns (`20261123000000_targets_proof_and_upload.sql`). Apply that last one before
  deploying a backend that uses it: the backend reads its columns.
- Put the project's secret key (`sb_secret_...`) in `SUPABASE_SECRET_KEY`. Without it, scans are
  kept in memory and lost when the server stops.
- There are no roles: every account has the same limits and sees only its own scans and APIs.
  Everything an operator does (approving APIs by hand, looking at users and scans) is done in the
  Supabase dashboard.

**Users' own APIs (proof, or approving them by hand)**
- A user adds an API on the Your APIs page; it is saved in `targets` with status `pending` and a
  random `verify_token`.
- Self-service: the user publishes `apifuzz-verify=<token>` in a file at
  `https://<their API>/.well-known/apifuzz-verify.txt` and presses Check now. The server fetches
  it (public address only, HTTPS with the certificate checked, no redirects, 64 KB at most; 10
  checks per account per 10 minutes), and if the line is there sets `status` to `approved` and
  `verified_at`. The file is fetched again before every scan of that API; if it's gone, the scan
  is refused.
- By hand: Supabase -> Table Editor -> `targets`, set `status` to `approved` or `rejected`, and
  optionally a short `note` the user sees (say why, when you reject). An API approved by hand has
  no `verified_at`, and its file is never checked. A rejected one can't be approved by the proof.
- Only approved APIs can be scanned, with two test-account tokens the user pastes for that scan
  (never stored). An uploaded spec is kept in `spec_text` (at most 1 MB, checked by the engine on
  upload; 6 uploads per account a minute) and is scanned without downloading anything. Every connection a scan opens is checked: HTTPS only, ports 443/8443, public
  addresses only (private, loopback, link-local/metadata and similar are refused, also when a name
  changes its answer mid-scan), no redirects, answers capped at 5 MB. A spec may not refer to other
  documents, and a YAML spec may not use aliases (they can expand without limit). Limits: `TARGETS_PER_USER` (default 3) and `SCANS_PER_TARGET_PER_DAY` (default 3).

**Google sign-in**
- The OAuth web client's id and secret go in `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`. Google
  shows a secret only once, when it is created.
- The client's authorized JavaScript origins must include the site's address. For local work:
  `http://localhost` and `http://localhost:5173`.

**E-mail (password reset and sign-in e-mails)**
- Supabase sends these through custom SMTP (Authentication -> Emails -> SMTP Settings), here
  Brevo: host `smtp-relay.brevo.com`, port `587`, the login and SMTP key from Brevo's
  "SMTP & API" page, and a sender verified in Brevo. The backend itself sends no e-mail, so the
  SMTP key is not in its settings.
- **The Brevo SMTP key expires after 90 days without use, even when it is created with "No
  expiration".** If no e-mail is sent for 90 days, password-reset e-mails stop arriving. Then
  generate a new key in Brevo and paste it into Supabase's SMTP settings.
- Sending as a `@gmail.com` address through Brevo can't be signed for that domain (Brevo warns
  about DKIM and DMARC), so some inboxes put the e-mails in spam. A domain of your own fixes it.

**Bot check on the e-mail forms (Cloudflare Turnstile)**
- In Cloudflare: Turnstile -> Add widget, mode Managed, with the site's hostnames (add `localhost`
  for local work). It gives a site key (public) and a secret key.
- The site key goes in the frontend's `VITE_TURNSTILE_SITE_KEY`. The secret key goes only into
  Supabase: Authentication -> Attack Protection -> Enable CAPTCHA protection, provider Turnstile.
  It is not a setting of this backend or the frontend.
- Order matters: deploy the frontend with the site key first, then switch protection on in
  Supabase. With protection on and no site key, e-mail sign-in, sign-up and password reset are
  refused. Google sign-in doesn't use it (Supabase doesn't ask for a check on that route).
- Testing: Cloudflare's test site key `1x00000000000000000000AA` always passes, but Supabase
  accepts its token only with the test secret `1x0000000000000000000000000000000AA`, so never
  leave a test secret in a real project.
