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

## What has to be set up outside this repository

**Supabase**
- Apply the migrations in [supabase/migrations](supabase/migrations) (the `scans` table and the
  server's grants on it).
- Put the project's secret key (`sb_secret_...`) in `SUPABASE_SECRET_KEY`. Without it, scans are
  kept in memory and lost when the server stops.
- Admins: set `app_metadata.role` to `"admin"` on the account (SQL editor), then sign in again.

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
