"""Scans that run in the background: their progress, and a way to cancel them.

A scan takes from a few seconds (the lab) to minutes (a sleeping API on free hosting), longer
than an HTTP request should stay open. So POST /scans starts a job and answers at once; the web
app then asks for the job's progress every few seconds until it is done.

Jobs live in this server's memory only. A finished scan is saved to the store like before, and
its job is forgotten a while later; a restart forgets running jobs (their scan simply never
finishes, and the web app says so). One server process holds all the state, which fits the
single free-tier instance this runs on.
"""

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

# The phases of a scan, in order, as the web app names them.
PHASES = ("waking", "spec", "login", "checks", "saving")

# How long a finished job is remembered, so the web app can still read how it ended.
KEEP_FINISHED_SECONDS = 30 * 60


@dataclass
class Job:
    id: str
    user_id: str
    label: str  # what was scanned, as the user knows it ("VulnShop lab", "Orders API")
    target: str  # its base URL
    checks: list[str]
    created_at: str
    max_requests: int
    status: str = "running"  # "running", "done", "failed"
    phase: str = "waking"
    check: str | None = None  # the check running now
    step: int = 0  # (check, endpoint) steps started
    steps: int = 0  # steps in the whole scan, once known
    requests_sent: int = 0
    error: str | None = None
    cancel_requested: bool = False
    stopped_early: bool = False  # cancelled after checks had started: the report is partial
    finished_at: float | None = None
    # The last few requests, for the live feed: (method, path, status or None if it failed).
    recent: deque[tuple[str, str, int | None]] = field(default_factory=lambda: deque(maxlen=8))
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ---- called by the scan, from its own thread ------------------------------------------------

    def set_phase(self, phase: str) -> None:
        with self._lock:
            self.phase = phase

    def on_step(self, check: str, index: int, total: int) -> None:
        with self._lock:
            self.phase, self.check, self.step, self.steps = "checks", check, index + 1, total

    def on_request(self, method: str, url: str, status: int | None) -> None:
        # Only the path: a query string can carry an API key, and the feed needs no more.
        path = urlsplit(url).path or "/"
        if len(path) > 80:
            path = path[:77] + "..."
        with self._lock:
            self.requests_sent += 1
            self.recent.append((method.upper(), path, status))

    def stop_reason(self) -> str | None:
        """What the engine asks between steps: a reason to stop, or None to go on."""
        return "cancelled by the user" if self._cancel.is_set() else None

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def finish(self, status: str, error: str | None = None, stopped_early: bool = False) -> None:
        with self._lock:
            self.status, self.error, self.stopped_early = status, error, stopped_early
            self.finished_at = time.monotonic()

    # ---- called by the routes ---------------------------------------------------------------------

    def request_cancel(self) -> None:
        with self._lock:
            if self.status == "running":
                self.cancel_requested = True
                self._cancel.set()

    def view(self) -> dict[str, Any]:
        """What the web app sees. Never the test accounts' tokens: the job doesn't hold them."""
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "target": self.target,
                "label": self.label,
                "checks": list(self.checks),
                "createdAt": self.created_at,
                "error": self.error,
                "cancelRequested": self.cancel_requested,
                "stoppedEarly": self.stopped_early,
                "progress": {
                    "phase": self.phase,
                    "check": self.check,
                    "step": self.step,
                    "steps": self.steps,
                    "requestsSent": self.requests_sent,
                    "maxRequests": self.max_requests,
                    "recent": [{"method": m, "path": p, "status": s} for m, p, s in self.recent],
                },
            }


class JobBoard:
    """Every job this server is running or finished recently."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def add(self, job: Job) -> None:
        with self._lock:
            self._forget_old()
            self._jobs[job.id] = job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            self._forget_old()
            return self._jobs.get(job_id)

    def running_for(self, user_id: str) -> Job | None:
        with self._lock:
            return next((j for j in self._jobs.values() if j.user_id == user_id and j.status == "running"), None)

    def _forget_old(self) -> None:
        now = self._clock()
        for job_id in [i for i, j in self._jobs.items()
                       if j.finished_at is not None and now - j.finished_at > KEEP_FINISHED_SECONDS]:
            del self._jobs[job_id]
