"""The server's settings, read once at start-up from the environment (and a local .env file).

Everything that decides what this server may scan lives here, set by whoever runs it. Nothing a
user sends can add a target: a scan request can only name one of the targets configured below.
"""

import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from apifuzz.settings import load_dotenv


class ConfigError(Exception):
    """A setting is missing or malformed. The server refuses to start rather than guess."""


@dataclass(frozen=True)
class Target:
    """An API this server is allowed to scan, with the test accounts it logs in as."""

    id: str
    label: str
    base_url: str  # an origin, e.g. "http://127.0.0.1:8000" (no path, no trailing slash)
    spec_url: str  # where its OpenAPI spec is; must be on the same origin
    # APIFUZZ_* settings handed to the engine for this target only (test accounts, login path).
    # The engine never reads the server's own environment.
    engine_env: dict[str, str] = field(default_factory=dict, repr=False)
    # Answers 200 with JSON once the target is up. Asked first, patiently, so a target that is
    # still starting (or asleep on free hosting) doesn't fail the scan. Empty: no such check.
    health_url: str = ""
    # A user's own API: every connection goes through the public-address guard (netguard), and
    # its answers are size-capped. False only for targets this server configures itself.
    guarded: bool = False
    # A spec the user uploaded instead of linking: scanned from this text, nothing downloaded.
    spec_text: str | None = field(default=None, repr=False)
    spec_name: str | None = None


@dataclass(frozen=True)
class Config:
    supabase_url: str  # https://<ref>.supabase.co
    # Server-only key for the scans table. Without it, scans are kept in memory (lost on restart).
    supabase_secret_key: str | None = field(default=None, repr=False)
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")
    targets: tuple[Target, ...] = ()
    scans_per_day: int = 5  # per account, reset at midnight UTC
    targets_per_user: int = 3  # own APIs one account may have, pending, approved or rejected
    scans_per_target_per_day: int = 3  # per own API, across all accounts, so no API gets hammered
    global_scans_per_day: int = 50  # across all users, so many accounts can't add up to a flood
    burst: int = 15  # requests the rate-limit check sends to one endpoint
    max_requests: int = 400  # a scan stops after this many requests
    request_timeout: float = 10.0  # seconds to wait for each response
    # Seconds a new scan waits for the one before it to end. Short: scans run in the background,
    # so the one before may take minutes, and the web app says another is running instead.
    scan_wait: float = 2.0
    retention_days: int = 30  # scans older than this are deleted
    requests_per_minute_ip: int = 60  # any request, per caller address
    requests_per_minute_user: int = 30  # signed-in requests, per account
    wake_timeout: float = 30.0  # seconds a scan waits for the target's health address to answer
    # True on Render: the caller's address is the last X-Forwarded-For entry, added by its proxy.
    behind_proxy: bool = False
    # Google sign-in from the web app's own button: the OAuth web client and its secret.
    google_client_id: str | None = None
    google_client_secret: str | None = field(default=None, repr=False)


def origin_of(url: str) -> str:
    """"http://host:port" for an http(s) URL, or raise ConfigError."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"not an http(s) URL with a host: {url!r}")
    if parts.username or parts.password:
        raise ConfigError(f"a URL in the settings must not carry a user name or password: {url!r}")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _int(env: dict[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}, got {value}")
    return value


def _lab(env: dict[str, str]) -> Target:
    base = origin_of(env.get("LAB_URL") or "http://127.0.0.1:8000")
    spec = (env.get("LAB_SPEC_URL") or f"{base}/openapi.json").strip()
    if origin_of(spec) != base:
        raise ConfigError("LAB_SPEC_URL must be on the same origin as LAB_URL")
    engine_env = {
        f"APIFUZZ_{key}": env[f"LAB_{key}"]
        for key in ("USER_A", "PASSWORD_A", "USER_B", "PASSWORD_B", "LOGIN_PATH")
        if env.get(f"LAB_{key}")
    }
    return Target(id="lab", label="VulnShop lab", base_url=base, spec_url=spec, engine_env=engine_env,
                  health_url=f"{base}/health")


def load_config(env: dict[str, str] | None = None) -> Config:
    if env is None:
        env = {**load_dotenv(), **os.environ}
    url = (env.get("SUPABASE_URL") or "").strip().rstrip("/")
    if not url:
        raise ConfigError("SUPABASE_URL is not set (https://<project-ref>.supabase.co)")
    if origin_of(url) != url:
        raise ConfigError("SUPABASE_URL must be just the project's address, with no path")
    if not url.startswith("https://") and urlsplit(url).hostname not in ("127.0.0.1", "localhost"):
        raise ConfigError("SUPABASE_URL must use https")
    origins = tuple(origin_of(o) for o in (env.get("ALLOWED_ORIGINS") or "").split(",") if o.strip())
    return Config(
        supabase_url=url,
        supabase_secret_key=(env.get("SUPABASE_SECRET_KEY") or "").strip() or None,
        allowed_origins=origins or Config.allowed_origins,
        targets=(_lab(env),),
        scans_per_day=_int(env, "SCANS_PER_DAY", 5, 1, 100),
        targets_per_user=_int(env, "TARGETS_PER_USER", 3, 0, 20),
        scans_per_target_per_day=_int(env, "SCANS_PER_TARGET_PER_DAY", 3, 1, 50),
        global_scans_per_day=_int(env, "GLOBAL_SCANS_PER_DAY", 50, 1, 10_000),
        burst=_int(env, "SCAN_BURST", 15, 2, 50),
        max_requests=_int(env, "SCAN_MAX_REQUESTS", 400, 10, 2000),
        retention_days=_int(env, "RETENTION_DAYS", 30, 1, 365),
        requests_per_minute_ip=_int(env, "REQUESTS_PER_MINUTE_IP", 60, 5, 6000),
        requests_per_minute_user=_int(env, "REQUESTS_PER_MINUTE_USER", 30, 5, 6000),
        wake_timeout=float(_int(env, "TARGET_WAKE_SECONDS", 30, 0, 300)),
        behind_proxy=(env.get("BEHIND_PROXY") or "").strip().lower() in ("1", "true", "yes"),
        google_client_id=(env.get("GOOGLE_CLIENT_ID") or "").strip() or None,
        google_client_secret=(env.get("GOOGLE_CLIENT_SECRET") or "").strip() or None,
    )
