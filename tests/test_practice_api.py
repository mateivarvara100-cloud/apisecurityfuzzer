# The public practice API (testapi/): the vulnerable variant gives one finding per planted flaw,
# the fixed variant gives none, and its proof file and hidden spec behave as documented. Scanned
# with the real CLI over HTTP, the way the hosted demo scans it.

import importlib.util
import json
import threading
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

import httpx
import pytest
from typer.testing import CliRunner

from apifuzz.cli import app as cli

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("practice_api", ROOT / "testapi" / "api" / "index.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class _Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def practice(monkeypatch):
    """Start the practice API; yields (base_url, set_env)."""
    module = _load()
    server = make_server("127.0.0.1", 0, module.app, handler_class=_Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", monkeypatch.setenv
    finally:
        server.shutdown()
        server.server_close()


def _scan(base: str, tmp_path, monkeypatch) -> dict:
    monkeypatch.chdir(tmp_path)  # no .env from the repository
    for name in ("APIFUZZ_USER_A", "APIFUZZ_PASSWORD_A", "APIFUZZ_USER_B", "APIFUZZ_PASSWORD_B"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APIFUZZ_TOKEN_A", "practice-token-alice")
    monkeypatch.setenv("APIFUZZ_TOKEN_B", "practice-token-bob")
    out = tmp_path / "report.json"
    result = CliRunner().invoke(cli, ["scan", f"{base}/openapi.json", "--base-url", base, "--i-have-authorization",
                                      "--no-require-docker", "--json-out", str(out)])
    assert out.exists(), result.output
    return json.loads(out.read_text(encoding="utf-8"))


PLANTED = {
    ("bola", "GET /orders/{id}"),
    ("auth-required", "GET /users/{id}"),
    ("mass-assignment", "POST /projects"),
    ("injection", "POST /login"),
    ("injection", "GET /search"),
    ("rate-limit", "POST /login"),
    ("rate-limit", "GET /search"),
}


def test_the_vulnerable_variant_shows_every_planted_flaw_and_nothing_else(practice, tmp_path, monkeypatch):
    base, _ = practice
    report = _scan(base, tmp_path, monkeypatch)
    assert {(f["check"], f["endpoint"]) for f in report["findings"]} == PLANTED
    # Injection on the login is the username only: the password is checked separately.
    assert {f["key"] for f in report["findings"] if f["endpoint"] == "POST /login" and f["check"] == "injection"} == {"username"}
    assert report["errors"] == []


def test_the_fixed_variant_shows_nothing(practice, tmp_path, monkeypatch):
    base, setenv = practice
    setenv("PRACTICE_VARIANT", "fixed")
    report = _scan(base, tmp_path, monkeypatch)
    assert report["findings"] == []
    # ...and that's because things were tested, not skipped.
    tested = {c["check"]: c["tested"] for c in report["coverage"]}
    assert all(tested[c] > 0 for c in ("auth-required", "bola", "injection", "mass-assignment", "rate-limit")), tested


def test_the_proof_file_serves_the_configured_lines(practice):
    base, setenv = practice
    assert httpx.get(f"{base}/.well-known/apifuzz-verify.txt").status_code == 404
    setenv("APIFUZZ_VERIFY", "apifuzz-verify=abc123 def456")
    r = httpx.get(f"{base}/.well-known/apifuzz-verify.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.text.splitlines() == ["apifuzz-verify=abc123", "apifuzz-verify=def456"]


def test_a_hidden_spec_is_not_published_and_the_file_in_the_folder_is_valid(practice):
    base, setenv = practice
    setenv("PRACTICE_SPEC", "hidden")
    assert httpx.get(f"{base}/openapi.json").status_code == 404
    from apifuzz.spec_loader import load_spec_text

    text = (ROOT / "testapi" / "openapi.json").read_text(encoding="utf-8")
    assert "/orders/{id}" in load_spec_text(text, "openapi.json", allow_yaml_aliases=False)["paths"]


def test_nothing_is_stored_and_ids_stay_short(practice):
    base, _ = practice
    auth = {"Authorization": "Bearer practice-token-alice"}
    created = httpx.post(f"{base}/projects", headers=auth, json={"name": "x", "role": "admin", "is_admin": True}).json()
    assert len(created["id"]) <= 64
    assert httpx.get(f"{base}/projects/{created['id']}", headers=auth).json()["role"] == "admin"
    # Someone else's project id is "not found"; a long or garbled id too.
    assert httpx.get(f"{base}/projects/{created['id']}", headers={"Authorization": "Bearer practice-token-bob"}).status_code == 404
    assert httpx.get(f"{base}/projects/{'e' * 65}", headers=auth).status_code == 404
    assert httpx.post(f"{base}/projects", headers=auth, json={"name": "x" * 100}).status_code == 400  # too long for an id
    assert httpx.post(f"{base}/projects", headers=auth, content=b"x" * 20_000).status_code == 413
