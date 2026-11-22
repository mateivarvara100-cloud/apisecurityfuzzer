"""Run one scan with the apifuzz engine, under the server's rules rather than the user's.

This follows the CLI's `scan` command step for step, with three differences that matter on a
server:

- The allowlist is the configured target's host and nothing else. The CLI builds it from what
  the user typed; here what the user typed is only used to pick a configured target.
- The spec download gets that same allowlist and never follows a redirect, so a spec URL can't
  make the server fetch anything else (server-side request forgery).
- The engine's settings come from the target's own entry, never from the server's environment
  or a .env file, so the server's secrets can't end up in a scan.

It also reports progress to the scan's job (jobs.py) and stops when the job is cancelled: before
the checks start, or between two checks' steps once they have, so no check is cut off halfway.
"""

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from apifuzz import __version__ as engine_version
from apifuzz.checks import ScanContext, all_checks, select_checks
from apifuzz.endpoint_model import build_endpoints
from apifuzz.errors import ApifuzzError
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.report import to_json
from apifuzz.scanner import run_scan
from apifuzz.session_manager import Reauthenticator, authenticate, preflight
from apifuzz.settings import host_entry, resolve_settings
from apifuzz.spec_loader import load_spec, load_spec_text

from apifuzz_web.config import Config, Target
from apifuzz_web.netguard import GuardedTransport, proxy_configured

CHECK_IDS = tuple(c.id for c in all_checks())


class ScanFailed(Exception):
    """The scan couldn't be completed. `requests_sent` says whether the target was reached."""

    def __init__(self, message: str, requests_sent: int = 0) -> None:
        super().__init__(message)
        self.requests_sent = requests_sent


@dataclass
class ScanOutcome:
    report: dict[str, Any]
    requests_sent: int
    stopped_early: bool = False  # cancelled once the checks had started: the report is partial


class Progress(Protocol):
    """What a scan reports to, and asks whether to stop. jobs.Job is the real one."""

    def set_phase(self, phase: str) -> None: ...
    def on_step(self, check: str, index: int, total: int) -> None: ...
    def on_request(self, method: str, url: str, status: int | None) -> None: ...
    def stop_reason(self) -> str | None: ...


class _Quiet:
    """Progress that goes nowhere, for scans nobody is watching."""

    def set_phase(self, phase: str) -> None:
        pass

    def on_step(self, check: str, index: int, total: int) -> None:
        pass

    def on_request(self, method: str, url: str, status: int | None) -> None:
        pass

    def stop_reason(self) -> str | None:
        return None


class _Watched(httpx.BaseTransport):
    """Passes every request on unchanged, and tells the progress what was sent and answered."""

    def __init__(self, inner: httpx.BaseTransport, progress: Progress) -> None:
        self._inner, self._progress = inner, progress

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            response = self._inner.handle_request(request)
        except Exception:
            self._progress.on_request(request.method, str(request.url), None)
            raise
        self._progress.on_request(request.method, str(request.url), response.status_code)
        return response

    def close(self) -> None:
        self._inner.close()


def in_engine_order(checks: list[str]) -> list[str]:
    """The chosen check ids, without repeats, in the order the engine runs them."""
    wanted = set(checks)
    return [c for c in CHECK_IDS if c in wanted]


def wake(
    url: str,
    within: float,
    *,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    stop_reason: Callable[[], str | None] = lambda: None,
) -> None:
    """Wait, for at most `within` seconds, until `url` answers 200 with JSON.

    The lab starts next to this server, and a host on free hosting sleeps when idle and takes
    about a minute to answer again. A scan waits only a few seconds per response, so it would
    fail against a target that is still starting. This asks the target's own health address
    first, without following redirects (a "starting up" page is not an answer), and raises
    ScanFailed with nothing sent to the API if the target doesn't come up in time.
    """
    if within <= 0:
        return
    deadline = clock() + within
    with httpx.Client(follow_redirects=False, transport=transport) as client:
        while (left := deadline - clock()) > 0:
            if stop_reason():
                raise ScanFailed("the scan was cancelled before it started.")
            try:
                answer = client.get(url, timeout=min(left, 30.0))
                if answer.status_code == 200 and answer.headers.get("content-type", "").startswith("application/json"):
                    return
            except httpx.HTTPError:
                pass  # not up yet
            sleep(min(2.0, max(0.0, deadline - clock())))
    raise ScanFailed(f"the target didn't answer within {round(within)} seconds. It may still be starting; "
                     "try again in a minute.")


def _stop_if_asked(progress: Progress, client: HttpClient | None) -> None:
    if progress.stop_reason():
        raise ScanFailed("the scan was cancelled before the checks started.", client.requests_sent if client else 0)


def scan_target(
    target: Target, spec_url: str, checks: list[str], config: Config, progress: Progress | None = None
) -> ScanOutcome:
    progress = progress or _Quiet()
    if target.health_url:
        progress.set_phase("waking")
        wake(target.health_url, config.wake_timeout, stop_reason=progress.stop_reason)
    inner: httpx.BaseTransport = httpx.HTTPTransport()
    spec_client: httpx.Client | None = None
    if target.guarded:
        # A user's API: every connection is checked and pinned to a public address (netguard).
        if proxy_configured():
            raise ScanFailed("this server has an HTTP proxy configured, so it can't scan outside APIs safely.")
        inner = GuardedTransport()
        if target.spec_text is None:
            spec_client = httpx.Client(transport=GuardedTransport(), timeout=15.0, follow_redirects=False,
                                       trust_env=False, headers={"User-Agent": f"apifuzz/{engine_version}"})
    allowlist = Allowlist([host_entry(target.base_url)])
    client: HttpClient | None = None
    stopped_early = False
    try:
        progress.set_phase("spec")
        # Specs come from people this server doesn't know, so YAML aliases are refused: a few
        # hundred bytes of them can keep the parser busy for hours.
        if target.spec_text is not None:
            source = target.spec_name or "the uploaded spec"
            document = load_spec_text(target.spec_text, source, allow_yaml_aliases=False)
        else:
            source = spec_url
            try:
                document = load_spec(spec_url, client=spec_client, follow_redirects=False, allowlist=allowlist,
                                     allow_yaml_aliases=False)
            finally:
                if spec_client is not None:
                    spec_client.close()
        _stop_if_asked(progress, None)
        settings = resolve_settings(
            spec=document,
            base_url=target.base_url,
            env=dict(target.engine_env),  # never os.environ
            burst=config.burst,
            concurrency=1,
            require_docker=False,
            spec_source=source,
        )
        endpoints = build_endpoints(document)
        chosen = select_checks(only=in_engine_order(checks))
        notes: list[str] = []
        with HttpClient(allowlist, timeout=config.request_timeout, max_requests=config.max_requests,
                        transport=_Watched(inner, progress)) as client:
            progress.set_phase("login")
            settings = authenticate(client, settings)
            notes += [f"warning: {line}" for line in preflight(client, settings, endpoints)]
            reauth = Reauthenticator(client, settings, endpoints)
            client.reauthenticate = reauth
            if any(c.id == "bola" for c in chosen) and not (settings.token_a and settings.token_b):
                notes.append("note: the bola check was skipped because this target has no second test account.")
            _stop_if_asked(progress, client)
            progress.set_phase("checks")
            result = run_scan(endpoints, chosen, ScanContext(client, settings),
                              on_step=progress.on_step, should_stop=progress.stop_reason)
            stopped_early = bool(progress.stop_reason())
            answered = client.responses_received
    except ApifuzzError as exc:
        # The engine's own messages: a refused host, a failed login, a broken spec, the request cap.
        raise ScanFailed(str(exc), client.requests_sent if client else 0) from exc
    if result.requests_sent and not answered:
        raise ScanFailed(f"no request to {target.base_url} got an answer, so nothing was tested.", result.requests_sent)
    progress.set_phase("saving")
    result.errors[:0] = notes + [f"note: {line}" for line in reauth.notes]
    # Shared reports never carry the test accounts' tokens, including ones renewed mid-scan.
    secrets = [settings.token_a, settings.token_b, *reauth.retired]
    report = json.loads(to_json(result, redact=True, secrets=secrets))
    return ScanOutcome(report=report, requests_sent=result.requests_sent, stopped_early=stopped_early)
