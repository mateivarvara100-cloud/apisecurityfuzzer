import importlib.util
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apifuzz_web.app import create_app
from apifuzz_web.auth import AuthError, User
from apifuzz_web.config import Config, Target
from apifuzz_web.engine import ScanFailed, ScanOutcome
from apifuzz_web.store import MemoryStore

ROOT = Path(__file__).resolve().parents[2]
LAB = "http://127.0.0.1:8000"

ALICE = User(id="11111111-1111-4111-8111-111111111111", email="a@example.test", is_admin=False)
BOB = User(id="22222222-2222-4222-8222-222222222222", email="b@example.test", is_admin=False)
ADMIN = User(id="33333333-3333-4333-8333-333333333333", email="admin@example.test", is_admin=True)
TOKENS = {"alice": ALICE, "bob": BOB, "admin": ADMIN}
NOW = datetime(2026, 11, 21, 15, 0, tzinfo=timezone.utc)


def auth(name: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {name}"}


class FakeVerifier:
    """Each test user's token is just their name."""

    def verify(self, token: str) -> User:
        if token not in TOKENS:
            raise AuthError("not a valid sign-in token")
        return TOKENS[token]


class FakeRunner:
    """Stands in for the engine; records what it was asked to do."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, list[str]]] = []
        self.fail: ScanFailed | None = None
        self.block: threading.Event | None = None
        self.started = threading.Event()

    def __call__(self, target: Target, spec_url: str, checks: list[str], config: Config) -> ScanOutcome:
        self.calls.append((target.base_url, spec_url, checks))
        self.started.set()
        if self.block:
            self.block.wait(5)
        if self.fail:
            raise self.fail
        return ScanOutcome(report={"findings": [], "coverage": [], "checks_run": checks}, requests_sent=12)


def make_config(**overrides) -> Config:
    lab = Target(id="lab", label="VulnShop lab", base_url=LAB, spec_url=f"{LAB}/openapi.json")
    values = {"supabase_url": "https://project.supabase.co", "targets": (lab,), "scan_wait": 0.2}
    values.update(overrides)
    return Config(**values)


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def clock():
    now = [NOW]
    return now


@pytest.fixture
def make_client(runner, store, clock):
    def _make(**overrides) -> TestClient:
        app = create_app(make_config(**overrides), store=store, verifier=FakeVerifier(),  # type: ignore[arg-type]
                         runner=runner, clock=lambda: clock[0])
        return TestClient(app)

    return _make


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client()


def scan_body(**overrides) -> dict:
    body = {"target": LAB, "specUrl": f"{LAB}/openapi.json", "checks": ["bola", "injection"], "authorized": True}
    body.update(overrides)
    return body


# The real VulnShop lab on a free local port, for end-to-end scans through the real engine.
@pytest.fixture
def lab_url():
    spec = importlib.util.spec_from_file_location("vulnshop_lab_web", ROOT / "lab" / "app.py")
    lab = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(lab)  # type: ignore[union-attr]
    lab.SPEC_PATH = ROOT / "lab" / "openapi.json"
    lab.Handler.log_message = lambda *a: None
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
