# apifuzz practice API

A small public API for trying **Your APIs** on the hosted demo: add it, prove you control it, scan
it, fix it, compare. **Fake data, simulated flaws**: two made-up users, a few made-up orders, no
database, no stored state, no requests to anywhere else. A planted flaw only behaves like one, so
there is nothing behind it to reach. (The VulnShop lab is different: it runs a real in-memory
database, so it stays private inside the backend.)

One folder, deployed as up to three Vercel projects that differ only in their settings:

| Project (suggested name) | `PRACTICE_VARIANT` | `PRACTICE_SPEC` | What you test with it |
| --- | --- | --- | --- |
| `apifuzz-practice` | `vulnerable` | `published` | Findings from every check; later switch it to `fixed` and compare |
| `apifuzz-practice-fixed` | `fixed` | `published` | A clean API: no findings, and a report that says what was tested |
| `apifuzz-practice-private` | `vulnerable` | `hidden` | A spec you have to upload ([openapi.json](openapi.json)) |

Test accounts (public; they exist only here): `alice` / `alice-practice`, token
`practice-token-alice`, and `bob` / `bob-practice`, token `practice-token-bob`. Paste the two
tokens as account A and B in the scan form.

What the vulnerable variant should report (checked by `tests/test_practice_api.py` on every run):

| Endpoint | Check |
| --- | --- |
| `GET /orders/{id}` | bola (critical): Alice can read Bob's order |
| `GET /users/{id}` | auth-required: answers without a token |
| `POST /projects` | mass-assignment (critical): `role`, `is_admin`, `verified` can be set |
| `POST /login` | injection (username) and rate-limit |
| `GET /search` | injection (`q`) and rate-limit |

The rate-limit check is off by default for your own API in the scan form: tick it to see those two.

## Deploy one (Vercel)

1. Vercel: **Add New -> Project**, import this repository.
2. **Root Directory**: `testapi`. Framework preset: **Other**. No build command.
3. **Environment Variables**: `PRACTICE_VARIANT` and `PRACTICE_SPEC` from the table (or leave both
   out for the vulnerable, published one).
4. Deploy. Open `https://<project>.vercel.app/health`: it names the variant.
5. Repeat for the other projects you want.

## Prove you control it

1. On the demo, **Your APIs -> Add an API**: address `https://<project>.vercel.app`, spec
   `https://<project>.vercel.app/openapi.json` (or upload `openapi.json` for the private one).
2. Copy the line it shows (`apifuzz-verify=...`).
3. In the Vercel project: **Settings -> Environment Variables**, add `APIFUZZ_VERIFY` with that line
   (several lines for several accounts: separate them with spaces), then **Deployments -> Redeploy**.
4. `https://<project>.vercel.app/.well-known/apifuzz-verify.txt` now shows the line. Press
   **Check now**.

`vercel.json` sends every request to the function with `routes`, not `rewrites`: with rewrites,
Vercel serves `openapi.json` from the folder as a static file first, so the private variant
couldn't hide it. Use the project's own `https://<project>.vercel.app` address; the longer
`...-<team>.vercel.app` ones are behind Vercel's login.

## Run it locally

```
python testapi/api/index.py 8020                         # vulnerable
PRACTICE_VARIANT=fixed python testapi/api/index.py 8021  # fixed
```

Standard library only, Python 3.11 or later.
