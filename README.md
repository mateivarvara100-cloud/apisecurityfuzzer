# apifuzz

A command-line tool that reads an OpenAPI/Swagger spec and (from Phase 1 on) runs automated
OWASP API Top 10 checks against an API you are authorized to test: BOLA/IDOR, mass assignment,
missing rate limits, and SQL/NoSQL injection.

> **Status: Phase 1 complete.** `scan` runs the `auth-required` and `bola` (BOLA/IDOR, token
> swapping) checks, logs in two test accounts itself, and writes a CLI, JSON or HTML report. It is
> verified against the bundled VulnShop lab. Mass assignment, rate limiting and injection follow.

## What this does (Phase 0)

You give it an OpenAPI spec (a file or a URL). It checks that the spec is valid, fills in all the
`$ref` shortcuts, and prints a table of every endpoint it found: the path, the method, the
parameters, the fields the request body takes, and whether the endpoint needs a login.

```text
$ apifuzz endpoints tests/data/sample_openapi.json
                       VulnShop (sample) 1.0.0
+-------------------------------------------------------------------+
| Method | Path         | Parameters | Body fields          | Auth  |
|--------+--------------+------------+----------------------+-------|
| POST   | /login       | -          | username*, password* | none  |
| GET    | /me          | -          | -                    | login |
| POST   | /orders      | -          | item*, quantity      | login |
| GET    | /orders/{id} | id (path)  | -                    | login |
| PATCH  | /users/{id}  | id (path)  | name, email          | login |
| GET    | /search      | q (query)  | -                    | none  |
+-------------------------------------------------------------------+
                             6 endpoints
```

A `*` after a body field means it is required.

## Install

Needs Python 3.11 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

This installs the `apifuzz` command.

## Use

```bash
apifuzz --version
apifuzz endpoints path/to/openapi.json
apifuzz endpoints https://staging.example.com/openapi.json
apifuzz endpoints path/to/openapi.json --json     # machine-readable output
```

Narrow the list down with filters (they can be combined; an endpoint must match all of them):

| Option | Keeps | Example |
| --- | --- | --- |
| `-m`, `--method` | endpoints with this HTTP method (repeatable, any case) | `-m GET -m PATCH` |
| `-p`, `--path` | paths matching a shell-style pattern (case-sensitive) | `-p '/orders*'`, `-p '*{id}'` |
| `-t`, `--tag` | endpoints with any of these tags (repeatable) | `-t admin` |
| `--auth` | endpoints that need a login (`login`) or don't (`none`) | `--auth none` |

When a filter hides endpoints, the caption says how many are left, e.g. `2 of 6 endpoints`.
Deprecated operations are shown dimmed, and `--json` output includes each endpoint's `tags` and
`deprecated` flag.

A broken spec, a missing file, a folder, or an unsupported URL scheme is rejected with a one-line
message and exit code 2. So is a mistyped option value such as `-m FETCH`.

## Scan (Phase 1)

```bash
apifuzz checks                                         # list the available checks
apifuzz scan openapi.json --i-have-authorization --base-url http://localhost:8000
```

`scan` refuses to run without `--i-have-authorization`. It contacts only the base URL's host, plus
any `--allow host[:port]` entries, and never follows redirects. Settings come from flags first,
then the environment or `.env` (see `.env.example`), then the spec's `servers` entry.

**Test accounts.** The `bola` check needs two different accounts, A and B. Give each one either a
token (`APIFUZZ_TOKEN_A` / `_B`) or a username and password (`APIFUZZ_USER_A` /
`APIFUZZ_PASSWORD_A`, and the same for B). With a username and password, apifuzz POSTs
`{"username", "password"}` to `APIFUZZ_LOGIN_PATH` (default `/login`) and reads the token from the
answer (`token`, `access_token`, ...). A failed login stops the scan. Credentials are read only from
the environment or `.env`, never from flags, so they stay out of shell history.

| Option | What it does |
| --- | --- |
| `--base-url` | Root URL of the API (default: `APIFUZZ_BASE_URL`, then the spec) |
| `--allow` | Extra host the scan may contact (repeatable) |
| `--only` / `--skip` | Run only, or leave out, a check id (repeatable) |
| `-m`, `-p`, `-t`, `--auth` | The same endpoint filters as `endpoints` |
| `--require-docker` | Only scan if every target is a running local Docker container (or set `APIFUZZ_REQUIRE_DOCKER=1`). See below. |
| `--timeout` | Seconds to wait for each response (default 10) |
| `--fail-on` | Exit 1 if any finding is at least this severe: `info`…`critical`, or `never` (default `high`) |
| `--json` | Machine-readable report on stdout |
| `--html FILE` | Also write a standalone HTML report (one file, inline CSS): findings grouped by severity, each expandable to its request/response evidence and fix |
| `--redact` / `--no-redact` | Hide `Authorization`, cookie and API-key values in JSON/HTML reports (default: on) |

Exit codes: `0` no findings at or above `--fail-on`, `1` findings at or above it, `2` usage or
configuration error. If an endpoint can't be reached, the scan prints a warning and carries on.

### Docker-only mode

With `--require-docker`, apifuzz asks Docker which containers are running before it sends
anything. It scans only if the base URL, and every `--allow` entry, is a port one of them
publishes. The host must be written as `localhost`, `127.0.0.1`, `::1`, or a container's own IP;
other hostnames are refused without a DNS lookup. The allowlist then holds only those exact
`host:port` pairs. Check a target on its own, without scanning, with:

```bash
apifuzz verify-docker http://localhost:8000
```

| Check | What it looks for |
| --- | --- |
| Check | OWASP | What it looks for |
| --- | --- | --- |
| `auth-required` | API2:2023 | An endpoint the spec says needs a login answers 2xx to a request with no credentials, twice. Only GET/HEAD are probed. HIGH. |
| `bola` | API1:2023 | Token swapping, see below. |

**How `bola` works.** First it does recon: it calls the protected GET endpoints that take no id
(such as `/me` or `/orders`) as account A and as account B, and notes which ids appear in each
account's own answers. Those real ids, plus 1–5, are requested on every `GET /thing/{id}`
endpoint as A and as B. An object that both accounts can read, while a request with no token is
refused, is reported once a second request confirms it:

- **CRITICAL** when ownership is proven. Either the object has an owner field (`owner`,
  `user_id`...), or recon found its id only in the other account's own data.
- **LOW** when it isn't proven. The object may be shared on purpose (a public profile, a
  product), so it's flagged for review.

Only GET endpoints with one integer path parameter are probed, and recon sends only GETs.

Every finding has a severity, its OWASP category, the evidence (the exact requests and
responses), and a fix. Every finding is confirmed by a repeated request before it's reported.
The summary line reads like `7 endpoints scanned · 2 findings (1 critical, 1 high)`.

## Lab target (Docker)

`lab/` contains VulnShop, a tiny deliberately vulnerable API (spec: [lab/openapi.json](lab/openapi.json)),
to try apifuzz on safely. Each planted flaw is marked `PLANTED` in [lab/app.py](lab/app.py), along
with the check that should find it; everything else behaves correctly. The container listens on
`127.0.0.1:8000` only, runs as a non-root user with a read-only filesystem and no capabilities,
and keeps its data in memory (seeded the same way on every start). The app refuses to start
without `DEMO_MODE=1` (docker-compose.yml sets it) and marks every response with an
`X-VulnShop-Lab` header, so it can't be mistaken for a real service.

| Route | Planted flaw | Should trigger |
| --- | --- | --- |
| `GET /orders/{id}` | Checks the login but not the order's owner | `bola` (CRITICAL) |
| `GET /users/{id}` | Doesn't check the login at all | `auth-required` (HIGH) |
| `GET /me` | None: correctly protected | nothing (false-positive guard) |

With `LAB_HARDENED=1` both flaws are fixed: orders and profiles are visible only to their owner.
This is the known-negative variant, and a scan of it must report nothing:

```bash
LAB_HARDENED=1 docker compose up -d --wait   # PowerShell: $env:LAB_HARDENED="1"; docker compose up -d --wait
```

`tests/test_phase1_complete.py` scans the real lab app in-process in both modes. It requires
exactly the table's results from the normal lab and no findings from the hardened one, so every
test run measures the scanner against this ground truth.

**One-command demo** (boots the lab, logs in both lab accounts, scans, writes `report.html`):

```bash
make demo                        # macOS/Linux, or Windows with make
powershell -File lab/demo.ps1    # Windows without make
```

Or step by step:

```bash
docker compose up -d --build --wait          # start (first run builds the image)
apifuzz verify-docker http://localhost:8000  # confirm it's the lab container
apifuzz scan http://localhost:8000/openapi.json --i-have-authorization --require-docker --html report.html
docker compose down                          # stop
```

Lab accounts: `alice`/`alice` (token `lab-token-alice`) and `bob`/`bob` (token `lab-token-bob`).
They are only for the lab, so it's fine to put them in `.env`, as either tokens
(`APIFUZZ_TOKEN_A` / `_B`) or usernames and passwords (`APIFUZZ_USER_A` / `APIFUZZ_PASSWORD_A`...).

## Run the tests

```bash
pytest
```

## How the code is laid out

| File | What it does |
| --- | --- |
| `src/apifuzz/spec_loader.py` | Reads a spec from a file or URL, resolves its `$ref`s, validates it, and turns problems into clear errors. |
| `src/apifuzz/endpoint_model.py` | Turns the spec into a plain list of `Endpoint` objects. |
| `src/apifuzz/http_client.py` | The only code that sends requests to a target. Refuses any host not on the allowlist, never follows redirects, and records the raw request and response as evidence. |
| `src/apifuzz/cli.py` | The `apifuzz` command: `endpoints`, `checks`, `scan`. |
| `src/apifuzz/settings.py` | Combines flags, environment/`.env` and the spec into scan settings. |
| `src/apifuzz/checks/` | One module per check. `base.py` defines `Check`, `ScanContext` and the registry. |
| `src/apifuzz/scanner.py` | Runs the chosen checks over the chosen endpoints and collects findings. |
| `src/apifuzz/finding.py` | The `Finding` record and severity scale. |
| `src/apifuzz/session_manager.py` | Logs the two test accounts in and gets their tokens. |
| `src/apifuzz/docker_verify.py` | `--require-docker`: confirms each target is a running local container. |
| `src/apifuzz/report.py` | Shows findings as a table, JSON or a standalone HTML report, with secrets redacted. |
| `src/apifuzz/errors.py` | The error types shown to the user as plain messages. |
| `tests/` | Unit tests plus `tests/data/sample_openapi.json`, a small VulnShop-shaped spec. `test_cli_options.py` covers the filters; `test_edge_cases.py` covers unusual specs, URLs and responses. |

## Scope & ethics

Use this only on APIs you own or have written permission to test. The HTTP client enforces a
host allowlist, and `scan` requires `--i-have-authorization`.
The tool detects flaws with minimal, non-destructive requests; it is not an exploitation tool.
