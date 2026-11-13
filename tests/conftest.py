# Shared test helpers. pytest loads this file automatically and makes its fixtures available
# to every test file in this folder.

import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"
ROOT = Path(__file__).resolve().parent.parent

# Every APIFUZZ_* setting. clean_env removes them all so a developer's own .env can't change a test.
_ENV_NAMES = (
    "BASE_URL", "ALLOWLIST", "TOKEN_A", "TOKEN_B", "USER_A", "PASSWORD_A", "USER_B", "PASSWORD_B",
    "LOGIN_PATH", "LOGIN_FORMAT", "LOGIN_USER_FIELD", "LOGIN_PASSWORD_FIELD", "AUTH_HEADER", "AUTH_PREFIX",
    "SHARED", "BURST", "REQUIRE_DOCKER",
)


def load_lab():
    """Import lab/app.py (the VulnShop lab) as a module, without needing Docker."""
    spec = importlib.util.spec_from_file_location("vulnshop_lab", ROOT / "lab" / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Runs the real lab app on a free local port for one test and gives the test its base URL.
@pytest.fixture
def lab_api():
    lab = load_lab()
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab.Handler)
    lab.Handler.log_message = lambda *a: None  # keep test output quiet
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


# Nothing from the real environment or the project's .env may leak into a scan under test.
# autouse: it applies to every test, so no test depends on the machine it runs on.
@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for name in _ENV_NAMES:
        monkeypatch.delenv(f"APIFUZZ_{name}", raising=False)
    monkeypatch.delenv("LAB_HARDENED", raising=False)
    monkeypatch.chdir(tmp_path)
    return monkeypatch


# Gives a test the path to the VulnShop-shaped sample spec in tests/data/.
@pytest.fixture
def sample_spec_path() -> Path:
    return DATA / "sample_openapi.json"


# Gives a test a function that writes a spec to a temporary file and returns its path.
@pytest.fixture
def write_spec(tmp_path):
    """Write a spec (dict -> JSON, str -> as-is) to a temp file and return its path as a string."""

    def _write(content, name: str = "spec.json") -> str:
        path = tmp_path / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return str(path)

    return _write


# Builds the smallest valid OpenAPI 3 spec; tests pass keyword arguments to add or replace parts.
def minimal_spec(**overrides) -> dict:
    spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}
    spec.update(overrides)
    return spec
