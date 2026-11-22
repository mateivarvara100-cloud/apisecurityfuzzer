"""The HTTP API the web app calls. Every route except /health needs a Supabase sign-in.

    GET    /health               is the server up (no sign-in; Render's health check)
    GET    /me                   who you are, your scans left today, the targets you may scan
    GET    /targets              your own APIs, whether each is approved, and how to prove each
    POST   /targets              add one of your APIs, with its spec linked or uploaded
    PUT    /targets/{id}/spec    change an API's spec (a new link or a new upload)
    POST   /targets/{id}/verify  look for the proof file on the API; approve it if it's there
    DELETE /targets/{id}         remove one of your APIs
    POST   /scans                start a scan in the background; answers at once with its job
    GET    /scans                your scans, newest first (an admin sees everyone's)
    GET    /scans/{id}           one scan: the report once done, else how it's going
    GET    /scans/{id}/progress  how a running scan is going (polled; its own rate limit)
    POST   /scans/{id}/cancel    stop a running scan; what it found so far is kept
    POST   /auth/google          finish a Google sign-in: trade Google's one-time code for its ID token
                                 (no sign-in needed: this is how one starts)

Someone else's scan or API always answers "not found", the same as one that doesn't exist.

Run locally:  uvicorn apifuzz_web.main:app --host 127.0.0.1 --port 8001
"""

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Literal
from urllib.parse import urlsplit

from apifuzz import __version__ as engine_version
from apifuzz.endpoint_model import build_endpoints
from apifuzz.errors import SpecError
from apifuzz.spec_loader import load_spec_text
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from apifuzz_web.auth import AuthError, AuthUnavailable, TokenVerifier, User
from apifuzz_web.config import Config, ConfigError, Target, load_config, origin_of
from apifuzz_web.engine import Progress, ScanFailed, ScanOutcome, in_engine_order, scan_target
from apifuzz_web.google import GoogleCodeExchange, GoogleSignInError, GoogleUnavailable
from apifuzz_web.guards import Guards, RateLimiter, client_ip
from apifuzz_web.jobs import Job, JobBoard
from apifuzz_web.netguard import BlockedAddress, check_user_url, public_addresses
from apifuzz_web.proof import PROOF_PATH, ProofMissing, check_proof, proof_line, proof_url
from apifuzz_web.store import MemoryStore, ScanRow, Store, StoreError, SupabaseStore, TargetRow, is_uuid

log = logging.getLogger("apifuzz_web")

CheckId = Literal["bola", "auth-required", "mass-assignment", "rate-limit", "injection"]
FormField = Literal["target", "specUrl", "spec", "authorized", "checks", "limit", "label", "url", "tokenA", "tokenB"]

MAX_SPEC_BYTES = 1_000_000  # an uploaded spec; the request carrying it may be a little larger


class Refused(Exception):
    """A request the user can fix: answered with a message and, when it fits, the form field."""

    def __init__(self, status: int, detail: str, field: FormField | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.field = status, detail, field


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(max_length=2048)
    # The lab's spec address. For the user's own API the server uses the spec stored with it, so
    # this may be empty; if it is sent, it must match.
    specUrl: str = Field(default="", max_length=2048)  # noqa: N815 (the web app's field name)
    checks: list[CheckId] = Field(min_length=1, max_length=5)
    authorized: bool
    # Bearer tokens of two test accounts on the user's own API. Used for this one scan, in memory
    # only: never stored, never logged, and removed from the report. Not used for the lab.
    tokenA: str | None = Field(default=None, max_length=4096)  # noqa: N815
    tokenB: str | None = Field(default=None, max_length=4096)  # noqa: N815


class SpecFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=255)
    text: str = Field(max_length=MAX_SPEC_BYTES)


class SpecIn(BaseModel):
    """A spec: linked (`specUrl`) or uploaded (`spec`), exactly one of the two."""

    model_config = ConfigDict(extra="forbid")

    specUrl: str | None = Field(default=None, max_length=2048)  # noqa: N815
    spec: SpecFile | None = None


class TargetIn(SpecIn):
    label: str = Field(max_length=200)
    url: str = Field(max_length=300)
    authorized: bool


class GoogleCodeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=10, max_length=2048)


Runner = Callable[[Target, str, list[str], Config, Progress], ScanOutcome]
ProofChecker = Callable[[str, str], None]  # (base_url, token); raises ProofMissing


def _midnight_utc(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _clean_token(value: str | None, field: FormField) -> str | None:
    """A pasted token, without a "Bearer " prefix or spaces; Refused if it can't be sent in a header."""
    token = (value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        return None
    if not all(33 <= ord(c) <= 126 for c in token):
        raise Refused(400, "That token has characters a request header can't carry. Paste just the token.", field)
    return token


def _file_name(name: str) -> str:
    """An uploaded file's name as shown back: no folders, no control characters, not too long."""
    base = PureWindowsPath(PurePosixPath(name).name).name
    cleaned = "".join(c for c in base if c.isprintable()).strip()
    return (cleaned or "spec")[:100]


def _in_background(work: Callable[[], None]) -> None:
    threading.Thread(target=work, daemon=True, name="scan").start()


def create_app(
    config: Config | None = None,
    *,
    store: Store | None = None,
    verifier: TokenVerifier | None = None,
    runner: Runner = scan_target,
    google: GoogleCodeExchange | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    start_background: Callable[[Callable[[], None]], None] = _in_background,
    proof_checker: ProofChecker = check_proof,
) -> FastAPI:
    config = config or load_config()
    if store is None:
        if config.supabase_secret_key:
            store = SupabaseStore(config.supabase_url, config.supabase_secret_key)
        else:
            log.warning("SUPABASE_SECRET_KEY is not set: scans are kept in memory and lost on restart")
            store = MemoryStore()
    verifier = verifier or TokenVerifier(config.supabase_url)
    user_limiter = RateLimiter(config.requests_per_minute_user, 60)
    # A running scan's page asks for progress every few seconds; that has its own allowance, so
    # watching a scan doesn't use up the account's general one.
    progress_limiter = RateLimiter(60, 60)
    # Each proof check fetches a file from the user's API: a few per account in ten minutes.
    verify_limiter = RateLimiter(10, 600)
    # Checking an uploaded spec takes some CPU: a few per account a minute.
    upload_limiter = RateLimiter(6, 60)
    google = google or GoogleCodeExchange(config.google_client_id, config.google_client_secret)
    # Signing in is rare: a tighter limit per address than the general one.
    sign_in_limiter = RateLimiter(10, 60)
    # One scan at a time on the whole server: the lab is shared, and the free tier is small.
    # Taken when a scan starts and released by the scan's own thread when it ends.
    scan_lock = threading.Lock()
    jobs = JobBoard()

    # No interactive docs: they load scripts from a CDN, and the API is documented in openapi.json.
    app = FastAPI(title="apifuzz web", version=engine_version, docs_url=None, redoc_url=None)
    # Added first, so it runs inside CORS: its 429 and 413 answers still carry CORS headers.
    app.add_middleware(
        Guards,
        ip_limiter=RateLimiter(config.requests_per_minute_ip, 60),
        behind_proxy=config.behind_proxy,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.allowed_origins),
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=False,  # the sign-in travels in the Authorization header, not a cookie
        max_age=600,
    )

    @app.exception_handler(Refused)
    async def refused(_: Request, exc: Refused) -> JSONResponse:
        return JSONResponse({"detail": exc.detail, "field": exc.field}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def malformed(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Pydantic's own report repeats the input back; say what is wrong without echoing it.
        fields = sorted({str(e["loc"][-1]) for e in exc.errors() if e.get("loc")})
        return JSONResponse({"detail": f"The request is malformed ({', '.join(fields) or 'body'})."}, status_code=400)

    # Declares "Authorization: Bearer <Supabase access token>" in openapi.json, so the spec says
    # which routes need a sign-in. auto_error=False: the answers below are ours, not FastAPI's.
    bearer = HTTPBearer(auto_error=False, scheme_name="supabase", bearerFormat="JWT",
                        description="The Supabase access token of the signed-in user.")

    def signed_in(credentials: HTTPAuthorizationCredentials | None, limiter: RateLimiter) -> User:
        token = credentials.credentials.strip() if credentials and credentials.scheme.lower() == "bearer" else ""
        if not token:
            raise HTTPException(401, "Sign in first.", headers={"WWW-Authenticate": "Bearer"})
        try:
            user = verifier.verify(token)
        except AuthError as exc:
            raise HTTPException(401, f"Sign in again: {exc}.", headers={"WWW-Authenticate": "Bearer"}) from exc
        except AuthUnavailable as exc:
            raise HTTPException(503, "Sign-in can't be checked right now. Try again in a minute.") from exc
        wait = limiter.hit(user.id)
        if wait is not None:
            raise HTTPException(429, "Too many requests. Wait a moment and try again.",
                                headers={"Retry-After": str(max(1, round(wait)))})
        return user

    def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
        return signed_in(credentials, user_limiter)

    def watching_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
        return signed_in(credentials, progress_limiter)

    def per_user(limiter: RateLimiter, user: User, message: str) -> None:
        wait = limiter.hit(user.id)
        if wait is not None:
            raise HTTPException(429, message, headers={"Retry-After": str(max(1, round(wait)))})

    def scans_left(user: User, now: datetime) -> int | None:
        if user.is_admin:
            return None
        used = store.count_since(_midnight_utc(now), user.id)
        return max(0, config.scans_per_day - used)

    def as_record(row: ScanRow, viewer: User) -> dict[str, Any]:
        record: dict[str, Any] = {
            "id": row.id, "status": "done", "target": row.target, "specUrl": row.spec_url, "checks": row.checks,
            "createdAt": row.created_at, "report": row.report,
        }
        if viewer.is_admin:
            record["ownerEmail"] = row.user_email
        return record

    def target_record(row: TargetRow, now: datetime) -> dict[str, Any]:
        record: dict[str, Any] = {
            "id": row.id, "label": row.label, "url": row.base_url, "specUrl": row.spec_url,
            "specName": row.spec_name, "status": row.status, "note": row.note, "createdAt": row.created_at,
            "verifiedAt": row.verified_at,
        }
        # How to prove control: while it waits, and for as long as a proven API is kept (the
        # proof is checked again before each scan). Not for one an admin decided on by hand.
        if row.status == "pending" or row.verified_at:
            record["proof"] = {"url": proof_url(row.base_url), "line": proof_line(row.verify_token)}
        if row.status == "approved":
            used = store.count_since(_midnight_utc(now), target=row.base_url)
            record["scansLeftToday"] = max(0, config.scans_per_target_per_day - used)
        return record

    def own_target_row(target_id: str, user: User) -> TargetRow:
        row = next((t for t in store.list_targets(user.id) if t.id == target_id), None) if is_uuid(target_id) else None
        if row is None:
            raise HTTPException(404, "No such API.")
        return row

    def read_spec(body: SpecIn, base_url: str) -> tuple[str | None, str | None, str | None]:
        """(spec_url, spec_name, spec_text) from a link or an upload, checked; Refused if not usable."""
        if (body.specUrl is None) == (body.spec is None):
            raise Refused(400, "Link the API's OpenAPI spec or upload it (one of the two).", "specUrl")
        if body.spec is None:
            spec_url = (body.specUrl or "").strip()
            try:
                spec_origin = check_user_url(spec_url)
            except ValueError as exc:
                raise Refused(400, f"The spec address: {exc}", "specUrl") from None
            if spec_origin != base_url:
                raise Refused(400, f"The spec has to be on the API's own address ({base_url}), because the server "
                                   "downloads it with the same safety rules as the scan. Or upload the file.",
                              "specUrl")
            if urlsplit(spec_url).path == PROOF_PATH:
                raise Refused(400, "That's the proof file's address, not the spec. Link the OpenAPI spec (often "
                                   "/openapi.json), or upload it.", "specUrl")
            return spec_url, None, None
        name, text = _file_name(body.spec.name), body.spec.text
        if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
            raise Refused(400, f"The spec is larger than {MAX_SPEC_BYTES // 1_000_000} MB.", "spec")
        try:
            document = load_spec_text(text, name, allow_yaml_aliases=False)
            endpoints = build_endpoints(document)
        except SpecError as exc:
            raise Refused(400, str(exc), "spec") from None
        except Exception:  # noqa: BLE001 - a spec the engine can't read, whatever the reason
            raise Refused(400, f"{name}: this file couldn't be read as an OpenAPI spec.", "spec") from None
        if not endpoints:
            raise Refused(400, f"{name}: the spec describes no endpoints, so there would be nothing to scan.", "spec")
        return None, name, text

    def own_target(body: ScanIn, user: User, target_origin: str) -> Target | None:
        """The user's own API at this address, ready to scan, or None if they have none there."""
        row = next((t for t in store.list_targets(user.id) if t.base_url == target_origin), None)
        if row is None:
            return None
        if row.status == "pending":
            raise Refused(403, f"{row.label} isn't approved yet. Prove that you control it under Your APIs, "
                               "then scan it.", "target")
        if row.status != "approved":
            raise Refused(403, f"{row.label} wasn't approved for scanning, so it can't be scanned.", "target")
        if body.specUrl.strip() and body.specUrl.strip() != (row.spec_url or ""):
            raise Refused(403, f"{row.label} is set up with a different spec now "
                               f"({row.spec_url or 'an uploaded file'}). Reload the page and try again.", "specUrl")
        tokens = {"APIFUZZ_TOKEN_A": _clean_token(body.tokenA, "tokenA"),
                  "APIFUZZ_TOKEN_B": _clean_token(body.tokenB, "tokenB")}
        if tokens["APIFUZZ_TOKEN_A"] and tokens["APIFUZZ_TOKEN_A"] == tokens["APIFUZZ_TOKEN_B"]:
            raise Refused(400, "Accounts A and B need different tokens: they have to be two different users.",
                          "tokenB")
        if row.verified_at:
            # Proven by a file on the API: it must still be there. Taking it down withdraws consent.
            try:
                proof_checker(row.base_url, row.verify_token)
            except ProofMissing as exc:
                raise Refused(403, f"The proof that you control {row.label} is gone: {exc}. Put the file back, "
                                   "then scan again.", "target") from None
        spec_text = store.get_spec_text(row.id, user.id) if row.spec_name else None
        if row.spec_name and spec_text is None:
            raise Refused(409, f"{row.label}'s uploaded spec is missing. Upload it again under Your APIs.", "target")
        return Target(id=row.id, label=row.label, base_url=row.base_url, spec_url=row.spec_url or "",
                      engine_env={k: v for k, v in tokens.items() if v}, guarded=True,
                      spec_text=spec_text, spec_name=row.spec_name)

    def pick_target(body: ScanIn, user: User) -> Target:
        try:
            target_origin = origin_of(body.target)
        except ConfigError:
            raise Refused(400, "Enter the target as a full address without a user name or password, "
                               "like http://127.0.0.1:8000.", "target") from None
        target = next((t for t in config.targets if t.base_url == target_origin), None)
        if target is None:
            mine = own_target(body, user, target_origin)
            if mine is not None:
                return mine
            labs = ", ".join(t.base_url for t in config.targets)
            raise Refused(403, f"{target_origin} isn't the lab ({labs}) or one of your approved APIs, so it "
                               "can't be scanned. Add it under Your APIs first.", "target")
        try:
            spec_origin = origin_of(body.specUrl)
        except ConfigError:
            raise Refused(400, "Enter the spec as a full address without a user name or password.", "specUrl") from None
        if spec_origin != target.base_url:
            raise Refused(403, "The spec is downloaded by the server too, so it must be on the target's own "
                               f"address ({target.base_url}).", "specUrl")
        return target

    def run_job(job: Job, row: ScanRow, target: Target, spec_url: str) -> None:
        """The scan itself, on its own thread. Releases the scan lock however it ends."""
        try:
            try:
                outcome = runner(target, spec_url, row.checks, config, job)
            except ScanFailed as exc:
                row.status, row.error, row.requests_sent = "failed", str(exc), exc.requests_sent
                if exc.requests_sent:  # it reached the target, so it counts towards the limits
                    store.add(row)
                job.finish("cancelled" if job.cancelled else "failed", error=str(exc))
                return
            except Exception:
                log.exception("scan %s stopped on an unexpected error", job.id)
                row.status, row.error, row.requests_sent = "failed", "unexpected server error", job.requests_sent
                if job.requests_sent:
                    store.add(row)
                job.finish("failed", error="the server hit an unexpected error. Try again later.")
                return
            row.report, row.requests_sent = outcome.report, outcome.requests_sent
            store.add(row)
            store.prune(clock() - timedelta(days=config.retention_days))
            job.finish("done", stopped_early=outcome.stopped_early)
        except StoreError as exc:
            log.error("database: %s", exc)
            job.finish("failed", error="the scan ran, but it couldn't be saved. Try again in a minute.")
        finally:
            scan_lock.release()

    @app.post("/auth/google")
    def google_sign_in(body: GoogleCodeIn, request: Request) -> dict[str, str]:
        wait = sign_in_limiter.hit(client_ip(request.scope, config.behind_proxy))
        if wait is not None:
            raise HTTPException(429, "Too many sign-in attempts. Wait a minute and try again.",
                                headers={"Retry-After": str(max(1, round(wait)))})
        try:
            return {"idToken": google.id_token_for(body.code)}
        except GoogleSignInError as exc:
            log.info("google sign-in refused: %s", exc)
            raise HTTPException(400, "Google didn't accept this sign-in. Try again.") from exc
        except GoogleUnavailable as exc:
            log.warning("google sign-in unavailable: %s", exc)
            raise HTTPException(503, "Google sign-in isn't available right now. Try e-mail, or again later.") from exc

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "engine": engine_version}

    @app.get("/me")
    def me(user: User = Depends(current_user)) -> dict[str, Any]:
        now = clock()
        running = jobs.running_for(user.id)
        return {
            "email": user.email,
            "isAdmin": user.is_admin,
            "scansPerDay": None if user.is_admin else config.scans_per_day,
            "scansLeftToday": scans_left(user, now),
            "resetsAt": (_midnight_utc(now) + timedelta(days=1)).isoformat(),
            "burst": config.burst,
            "targets": [{"id": t.id, "label": t.label, "url": t.base_url, "specUrl": t.spec_url}
                        for t in config.targets],
            "runningScan": {"id": running.id, "label": running.label} if running else None,
        }

    @app.post("/scans", status_code=202)
    def start_scan(body: ScanIn, user: User = Depends(current_user)) -> dict[str, Any]:
        if not body.authorized:
            raise Refused(400, "Confirm that you own this target or have written permission to test it.",
                          "authorized")
        target = pick_target(body, user)
        checks = in_engine_order(list(body.checks))
        if not scan_lock.acquire(timeout=config.scan_wait):
            mine = jobs.running_for(user.id)
            if mine is not None:
                raise Refused(409, f"Your scan of {mine.label} is still running. Wait for it to finish, or cancel it.")
            raise Refused(503, "Another scan is running. Try again in a minute.")
        try:
            # Counted while holding the lock, so two requests at once can't both take the last scan.
            now = clock()
            if not user.is_admin:
                if store.count_since(_midnight_utc(now), user.id) >= config.scans_per_day:
                    raise Refused(429, f"You've used all {config.scans_per_day} scans for today. "
                                       "The count resets at midnight UTC.", "limit")
                if store.count_since(_midnight_utc(now)) >= config.global_scans_per_day:
                    raise Refused(429, "This server has run all the scans it allows today. "
                                       "Try again after midnight UTC.", "limit")
                if target.guarded and (store.count_since(_midnight_utc(now), target=target.base_url)
                                       >= config.scans_per_target_per_day):
                    raise Refused(429, f"{target.label} has been scanned {config.scans_per_target_per_day} times "
                                       "today, the most one API may be. Try again after midnight UTC.", "limit")
            spec_source = target.spec_url if target.spec_text is None else f"uploaded: {target.spec_name}"
            created = now.isoformat(timespec="seconds")
            job = Job(id=str(uuid.uuid4()), user_id=user.id, label=target.label, target=target.base_url,
                      checks=checks, created_at=created, max_requests=config.max_requests)
            row = ScanRow(user_id=user.id, user_email=user.email, target=target.base_url, spec_url=spec_source,
                          checks=checks, status="done", requests_sent=0, created_at=created, id=job.id)
            jobs.add(job)
            spec_url = body.specUrl if target.spec_text is None and not target.guarded else target.spec_url
            start_background(lambda: run_job(job, row, target, spec_url))
        except BaseException:
            scan_lock.release()  # the scan never started, so its thread won't release it
            raise
        log.info("scan %s started on %s by %s", job.id, target.base_url, user.id)
        return job.view()

    @app.get("/scans")
    def list_scans(user: User = Depends(current_user)) -> list[dict[str, Any]]:
        rows = store.list(None if user.is_admin else user.id)
        return [as_record(r, user) for r in rows]

    def visible_job(scan_id: str, user: User) -> Job | None:
        job = jobs.get(scan_id) if is_uuid(scan_id) else None
        return job if job is not None and (job.user_id == user.id or user.is_admin) else None

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str, user: User = Depends(current_user)) -> dict[str, Any]:
        job = visible_job(scan_id, user)
        if job is not None and job.status != "done":
            return job.view()
        row = store.get(scan_id) if is_uuid(scan_id) else None
        # Someone else's scan looks exactly like a missing one, so ids can't be probed.
        if row is None or row.status != "done" or (row.user_id != user.id and not user.is_admin):
            raise HTTPException(404, "No such scan.")
        return as_record(row, user)

    @app.get("/scans/{scan_id}/progress")
    def scan_progress(scan_id: str, user: User = Depends(watching_user)) -> dict[str, Any]:
        job = visible_job(scan_id, user)
        if job is not None:
            return job.view()
        row = store.get(scan_id) if is_uuid(scan_id) else None
        if row is not None and row.status == "done" and (row.user_id == user.id or user.is_admin):
            return {"id": row.id, "status": "done"}
        raise HTTPException(404, "No such scan. If it was running, the server may have restarted.")

    @app.post("/scans/{scan_id}/cancel", status_code=202)
    def cancel_scan(scan_id: str, user: User = Depends(current_user)) -> dict[str, Any]:
        job = visible_job(scan_id, user)
        if job is None:
            raise HTTPException(404, "No such running scan.")
        job.request_cancel()
        if job.cancel_requested:
            log.info("scan %s cancelled by %s", job.id, user.id)
        return job.view()

    @app.get("/targets")
    def list_targets(user: User = Depends(current_user)) -> dict[str, Any]:
        now = clock()
        return {
            "targets": [target_record(t, now) for t in store.list_targets(user.id)],
            "maxTargets": config.targets_per_user,
            "scansPerTargetPerDay": config.scans_per_target_per_day,
        }

    @app.post("/targets", status_code=201)
    def add_target(body: TargetIn, user: User = Depends(current_user)) -> dict[str, Any]:
        if not body.authorized:
            raise Refused(400, "Confirm that you own this API or have written permission to test it.",
                          "authorized")
        label = " ".join(body.label.split())
        if not 1 <= len(label) <= 60:
            raise Refused(400, "Give the API a name of 1 to 60 characters.", "label")
        try:
            base_url = check_user_url(body.url)
        except ValueError as exc:
            raise Refused(400, str(exc), "url") from None
        mine = store.list_targets(user.id)
        if any(t.base_url == base_url for t in mine):
            raise Refused(409, "You've already added that API.", "url")
        if not user.is_admin and len(mine) >= config.targets_per_user:
            raise Refused(429, f"You can have {config.targets_per_user} APIs at most. Remove one to add another.",
                          "limit")
        if body.spec is not None:
            per_user(upload_limiter, user, "Too many uploads. Wait a minute and try again.")
        spec_url, spec_name, spec_text = read_spec(body, base_url)
        host, _, port = base_url.removeprefix("https://").partition(":")
        try:
            public_addresses(host, int(port or 443))  # an early, clear answer; every scan checks again
        except BlockedAddress as exc:
            raise Refused(400, f"{exc}. Only APIs on the public internet can be scanned.", "url") from None
        row = TargetRow(user_id=user.id, user_email=user.email, label=label, base_url=base_url,
                        spec_url=spec_url, spec_name=spec_name, spec_text=spec_text,
                        created_at=clock().isoformat(timespec="seconds"))
        store.add_target(row)
        log.info("target added: %s by %s", base_url, user.id)
        return target_record(row, clock())

    @app.put("/targets/{target_id}/spec")
    def replace_spec(target_id: str, body: SpecIn, user: User = Depends(current_user)) -> dict[str, Any]:
        row = own_target_row(target_id, user)
        if body.spec is not None:
            per_user(upload_limiter, user, "Too many uploads. Wait a minute and try again.")
        spec_url, spec_name, spec_text = read_spec(body, row.base_url)
        if not store.set_spec(row.id, user.id, spec_url, spec_name, spec_text):
            raise HTTPException(404, "No such API.")
        row.spec_url, row.spec_name = spec_url, spec_name
        return target_record(row, clock())

    @app.post("/targets/{target_id}/verify")
    def verify_target(target_id: str, user: User = Depends(current_user)) -> dict[str, Any]:
        row = own_target_row(target_id, user)
        if row.status == "approved":
            return target_record(row, clock())
        if row.status == "rejected":
            raise Refused(403, f"An admin decided {row.label} can't be scanned, so it can't be approved this way.")
        per_user(verify_limiter, user, "Too many checks. Wait a few minutes, then check again.")
        try:
            proof_checker(row.base_url, row.verify_token)
        except ProofMissing as exc:
            raise Refused(422, f"The proof wasn't found: {exc}.") from None
        when = clock().isoformat(timespec="seconds")
        if not store.mark_verified(row.id, user.id, when):
            raise HTTPException(404, "No such API.")  # removed, or decided by an admin, meanwhile
        row.status, row.verified_at = "approved", when
        log.info("target verified: %s by %s", row.base_url, user.id)
        return target_record(row, clock())

    @app.delete("/targets/{target_id}", status_code=204)
    def delete_target(target_id: str, user: User = Depends(current_user)) -> None:
        # Someone else's target looks exactly like a missing one.
        if not is_uuid(target_id) or not store.delete_target(target_id, user.id):
            raise HTTPException(404, "No such API.")

    @app.exception_handler(StoreError)
    async def store_down(_: Request, exc: StoreError) -> JSONResponse:
        log.error("database: %s", exc)
        return JSONResponse({"detail": "Saved scans and APIs are unavailable right now. Try again in a minute."},
                            status_code=503)

    return app
