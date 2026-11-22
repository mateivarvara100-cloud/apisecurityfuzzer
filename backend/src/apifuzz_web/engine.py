"""Run one scan with the apifuzz engine, under the server's rules rather than the user's.

This follows the CLI's `scan` command step for step, with three differences that matter on a
server:

- The allowlist is the configured target's host and nothing else. The CLI builds it from what
  the user typed; here what the user typed is only used to pick a configured target.
- The spec download gets that same allowlist and never follows a redirect, so a spec URL can't
  make the server fetch anything else (server-side request forgery).
- The engine's settings come from the target's own entry, never from the server's environment
  or a .env file, so the server's secrets can't end up in a scan.
"""

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from apifuzz.checks import ScanContext, all_checks, select_checks
from apifuzz.endpoint_model import build_endpoints
from apifuzz.errors import ApifuzzError
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.report import to_json
from apifuzz.scanner import run_scan
from apifuzz.session_manager import Reauthenticator, authenticate, preflight
from apifuzz.settings import host_entry, resolve_settings
from apifuzz.spec_loader import load_spec

from apifuzz_web.config import Config, Target

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
            try:
                answer = client.get(url, timeout=min(left, 30.0))
                if answer.status_code == 200 and answer.headers.get("content-type", "").startswith("application/json"):
                    return
            except httpx.HTTPError:
                pass  # not up yet
            sleep(min(2.0, max(0.0, deadline - clock())))
    raise ScanFailed(f"the target didn't answer within {round(within)} seconds. It may still be starting; "
                     "try again in a minute.")


def scan_target(target: Target, spec_url: str, checks: list[str], config: Config) -> ScanOutcome:
    if target.health_url:
        wake(target.health_url, config.wake_timeout)
    allowlist = Allowlist([host_entry(target.base_url)])
    client: HttpClient | None = None
    try:
        document = load_spec(spec_url, follow_redirects=False, allowlist=allowlist)
        settings = resolve_settings(
            spec=document,
            base_url=target.base_url,
            env=dict(target.engine_env),  # never os.environ
            burst=config.burst,
            concurrency=1,
            require_docker=False,
            spec_source=spec_url,
        )
        endpoints = build_endpoints(document)
        chosen = select_checks(only=in_engine_order(checks))
        notes: list[str] = []
        with HttpClient(allowlist, timeout=config.request_timeout, max_requests=config.max_requests) as client:
            settings = authenticate(client, settings)
            notes += [f"warning: {line}" for line in preflight(client, settings, endpoints)]
            reauth = Reauthenticator(client, settings, endpoints)
            client.reauthenticate = reauth
            if any(c.id == "bola" for c in chosen) and not (settings.token_a and settings.token_b):
                notes.append("note: the bola check was skipped because this target has no second test account.")
            result = run_scan(endpoints, chosen, ScanContext(client, settings))
            answered = client.responses_received
    except ApifuzzError as exc:
        # The engine's own messages: a refused host, a failed login, a broken spec, the request cap.
        raise ScanFailed(str(exc), client.requests_sent if client else 0) from exc
    if result.requests_sent and not answered:
        raise ScanFailed(f"no request to {target.base_url} got an answer, so nothing was tested.", result.requests_sent)
    result.errors[:0] = notes + [f"note: {line}" for line in reauth.notes]
    # Shared reports never carry the test accounts' tokens, including ones renewed mid-scan.
    secrets = [settings.token_a, settings.token_b, *reauth.retired]
    report = json.loads(to_json(result, redact=True, secrets=secrets))
    return ScanOutcome(report=report, requests_sent=result.requests_sent)
