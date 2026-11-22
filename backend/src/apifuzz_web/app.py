"""The HTTP API the web app calls. Every route except /health needs a Supabase sign-in.

    GET  /health       is the server up (no sign-in; Render's health check)
    GET  /me           who you are, your scans left today, the targets you may scan
    GET  /targets      your own APIs and whether each is approved
    POST /targets      ask for one of your APIs to be added (an admin approves it)
    DELETE /targets/{id}  remove one of your APIs
    POST /scans        run a scan; answers with the finished report
    GET  /scans        your scans, newest first (an admin sees everyone's)
    GET  /scans/{id}   one scan; someone else's is "not found", the same as one that doesn't exist
    POST /auth/google  finish a Google sign-in: trade Google's one-time code for its ID token
                       (no sign-in needed: this is how one starts)

Run locally:  uvicorn apifuzz_web.main:app --host 127.0.0.1 --port 8001
"""

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from apifuzz import __version__ as engine_version
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from apifuzz_web.auth import AuthError, AuthUnavailable, TokenVerifier, User
from apifuzz_web.config import Config, ConfigError, Target, load_config, origin_of
from apifuzz_web.engine import ScanFailed, ScanOutcome, in_engine_order, scan_target
from apifuzz_web.google import GoogleCodeExchange, GoogleSignInError, GoogleUnavailable
from apifuzz_web.guards import Guards, RateLimiter, client_ip
from apifuzz_web.netguard import BlockedAddress, check_user_url, public_addresses
from apifuzz_web.store import MemoryStore, ScanRow, Store, StoreError, SupabaseStore, TargetRow, is_uuid

log = logging.getLogger("apifuzz_web")

CheckId = Literal["bola", "auth-required", "mass-assignment", "rate-limit", "injection"]
FormField = Literal["target", "specUrl", "authorized", "checks", "limit", "label", "url", "tokenA", "tokenB"]


class Refused(Exception):
    """A request the user can fix: answered with a message and, when it fits, the form field."""

    def __init__(self, status: int, detail: str, field: FormField | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.field = status, detail, field


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(max_length=2048)
    specUrl: str = Field(max_length=2048)  # noqa: N815 (the web app's field name)
    checks: list[CheckId] = Field(min_length=1, max_length=5)
    authorized: bool
    # Bearer tokens of two test accounts on the user's own API. Used for this one scan, in memory
    # only: never stored, never logged, and removed from the report. Not used for the lab.
    tokenA: str | None = Field(default=None, max_length=4096)  # noqa: N815
    tokenB: str | None = Field(default=None, max_length=4096)  # noqa: N815


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(max_length=200)
    url: str = Field(max_length=300)
    specUrl: str = Field(max_length=2048)  # noqa: N815
    authorized: bool


class GoogleCodeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=10, max_length=2048)


Runner = Callable[[Target, str, list[str], Config], ScanOutcome]


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


def create_app(
    config: Config | None = None,
    *,
    store: Store | None = None,
    verifier: TokenVerifier | None = None,
    runner: Runner = scan_target,
    google: GoogleCodeExchange | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
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
    google = google or GoogleCodeExchange(config.google_client_id, config.google_client_secret)
    # Signing in is rare: a tighter limit per address than the general one.
    sign_in_limiter = RateLimiter(10, 60)
    # One scan at a time on the whole server: the lab is shared, and the free tier is small.
    scan_lock = threading.Lock()

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
        allow_methods=["GET", "POST", "DELETE"],
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

    def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> User:
        token = credentials.credentials.strip() if credentials and credentials.scheme.lower() == "bearer" else ""
        if not token:
            raise HTTPException(401, "Sign in first.", headers={"WWW-Authenticate": "Bearer"})
        try:
            user = verifier.verify(token)
        except AuthError as exc:
            raise HTTPException(401, f"Sign in again: {exc}.", headers={"WWW-Authenticate": "Bearer"}) from exc
        except AuthUnavailable as exc:
            raise HTTPException(503, "Sign-in can't be checked right now. Try again in a minute.") from exc
        wait = user_limiter.hit(user.id)
        if wait is not None:
            raise HTTPException(429, "Too many requests. Wait a moment and try again.",
                                headers={"Retry-After": str(max(1, round(wait)))})
        return user

    def scans_left(user: User, now: datetime) -> int | None:
        if user.is_admin:
            return None
        used = store.count_since(_midnight_utc(now), user.id)
        return max(0, config.scans_per_day - used)

    def as_record(row: ScanRow, viewer: User) -> dict[str, Any]:
        record: dict[str, Any] = {
            "id": row.id, "target": row.target, "specUrl": row.spec_url, "checks": row.checks,
            "createdAt": row.created_at, "report": row.report,
        }
        if viewer.is_admin:
            record["ownerEmail"] = row.user_email
        return record

    def target_record(row: TargetRow, now: datetime) -> dict[str, Any]:
        record: dict[str, Any] = {
            "id": row.id, "label": row.label, "url": row.base_url, "specUrl": row.spec_url,
            "status": row.status, "note": row.note, "createdAt": row.created_at,
        }
        if row.status == "approved":
            used = store.count_since(_midnight_utc(now), target=row.base_url)
            record["scansLeftToday"] = max(0, config.scans_per_target_per_day - used)
        return record

    def own_target(body: ScanIn, user: User, target_origin: str) -> Target | None:
        """The user's own API at this address, ready to scan, or None if they have none there."""
        row = next((t for t in store.list_targets(user.id) if t.base_url == target_origin), None)
        if row is None:
            return None
        if row.status == "pending":
            raise Refused(403, f"{row.label} is waiting for approval. You can scan it once an admin approves it.",
                          "target")
        if row.status != "approved":
            raise Refused(403, f"{row.label} wasn't approved for scanning, so it can't be scanned.", "target")
        if body.specUrl.strip() != row.spec_url:
            raise Refused(403, f"Scan {row.label} with the spec it was approved with: {row.spec_url}", "specUrl")
        tokens = {"APIFUZZ_TOKEN_A": _clean_token(body.tokenA, "tokenA"),
                  "APIFUZZ_TOKEN_B": _clean_token(body.tokenB, "tokenB")}
        if tokens["APIFUZZ_TOKEN_A"] and tokens["APIFUZZ_TOKEN_A"] == tokens["APIFUZZ_TOKEN_B"]:
            raise Refused(400, "Accounts A and B need different tokens: they have to be two different users.",
                          "tokenB")
        return Target(id=row.id, label=row.label, base_url=row.base_url, spec_url=row.spec_url,
                      engine_env={k: v for k, v in tokens.items() if v}, guarded=True)

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
        return {
            "email": user.email,
            "isAdmin": user.is_admin,
            "scansPerDay": None if user.is_admin else config.scans_per_day,
            "scansLeftToday": scans_left(user, now),
            "resetsAt": (_midnight_utc(now) + timedelta(days=1)).isoformat(),
            "burst": config.burst,
            "targets": [{"id": t.id, "label": t.label, "url": t.base_url, "specUrl": t.spec_url}
                        for t in config.targets],
        }

    @app.post("/scans", status_code=201)
    def start_scan(body: ScanIn, user: User = Depends(current_user)) -> dict[str, Any]:
        if not body.authorized:
            raise Refused(400, "Confirm that you own this target or have written permission to test it.",
                          "authorized")
        target = pick_target(body, user)
        checks = in_engine_order(list(body.checks))
        if not scan_lock.acquire(timeout=config.scan_wait):
            raise Refused(503, "Another scan is running. Try again in a minute.")
        try:
            # Counted inside the lock, so two requests at once can't both take the last scan.
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
            row = ScanRow(user_id=user.id, user_email=user.email, target=target.base_url,
                          spec_url=body.specUrl, checks=checks, status="done", requests_sent=0,
                          created_at=now.isoformat(timespec="seconds"))
            try:
                outcome = runner(target, body.specUrl, checks, config)
            except ScanFailed as exc:
                row.status, row.error, row.requests_sent = "failed", str(exc), exc.requests_sent
                if exc.requests_sent:  # it reached the target, so it counts towards the limits
                    store.add(row)
                raise Refused(502, f"The scan stopped: {exc}") from exc
            row.report, row.requests_sent = outcome.report, outcome.requests_sent
            store.add(row)
            store.prune(now - timedelta(days=config.retention_days))
            return as_record(row, user)
        finally:
            scan_lock.release()

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
        spec_url = body.specUrl.strip()
        try:
            spec_origin = check_user_url(spec_url)
        except ValueError as exc:
            raise Refused(400, f"The spec address: {exc}", "specUrl") from None
        if spec_origin != base_url:
            raise Refused(400, f"The spec has to be on the API's own address ({base_url}), because the server "
                               "downloads it with the same safety rules as the scan.", "specUrl")
        mine = store.list_targets(user.id)
        if any(t.base_url == base_url for t in mine):
            raise Refused(409, "You've already added that API.", "url")
        if not user.is_admin and len(mine) >= config.targets_per_user:
            raise Refused(429, f"You can have {config.targets_per_user} APIs at most. Remove one to add another.",
                          "limit")
        host, _, port = base_url.removeprefix("https://").partition(":")
        try:
            public_addresses(host, int(port or 443))  # an early, clear answer; every scan checks again
        except BlockedAddress as exc:
            raise Refused(400, f"{exc}. Only APIs on the public internet can be scanned.", "url") from None
        row = TargetRow(user_id=user.id, user_email=user.email, label=label, base_url=base_url,
                        spec_url=spec_url, created_at=clock().isoformat(timespec="seconds"))
        store.add_target(row)
        log.info("target requested: %s by %s", base_url, user.id)
        return target_record(row, clock())

    @app.delete("/targets/{target_id}", status_code=204)
    def delete_target(target_id: str, user: User = Depends(current_user)) -> None:
        # Someone else's target looks exactly like a missing one.
        if not is_uuid(target_id) or not store.delete_target(target_id, user.id):
            raise HTTPException(404, "No such API.")

    @app.get("/scans")
    def list_scans(user: User = Depends(current_user)) -> list[dict[str, Any]]:
        rows = store.list(None if user.is_admin else user.id)
        return [as_record(r, user) for r in rows]

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str, user: User = Depends(current_user)) -> dict[str, Any]:
        row = store.get(scan_id) if is_uuid(scan_id) else None
        # Someone else's scan looks exactly like a missing one, so ids can't be probed.
        if row is None or row.status != "done" or (row.user_id != user.id and not user.is_admin):
            raise HTTPException(404, "No such scan.")
        return as_record(row, user)

    @app.exception_handler(StoreError)
    async def store_down(_: Request, exc: StoreError) -> JSONResponse:
        log.error("database: %s", exc)
        return JSONResponse({"detail": "Saved scans and APIs are unavailable right now. Try again in a minute."},
                            status_code=503)

    return app

