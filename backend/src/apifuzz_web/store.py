"""Where scans are kept: the `scans` table in Supabase, or memory when no key is configured.

The table has row level security on and no policies (see supabase/migrations), so browsers can't
read or write it at all, even with a valid sign-in. Only this server can, with the secret key, and
it decides who sees what: a user their own scans, an admin everyone's.
"""

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Protocol

import httpx


@dataclass
class ScanRow:
    user_id: str
    user_email: str
    target: str
    spec_url: str
    checks: list[str]
    status: str  # "done" or "failed"
    requests_sent: int
    created_at: str  # UTC, ISO 8601
    report: dict[str, Any] | None = None
    error: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


class StoreError(Exception):
    """The database didn't answer as expected."""


class Store(Protocol):
    kind: str

    def add(self, row: ScanRow) -> None: ...
    def get(self, scan_id: str) -> ScanRow | None: ...
    def list(self, user_id: str | None, limit: int = 50) -> list[ScanRow]: ...
    def count_since(self, since: datetime, user_id: str | None = None) -> int: ...
    def prune(self, before: datetime) -> None: ...


def is_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


class MemoryStore:
    """For local development and tests. Everything is lost when the server stops."""

    kind = "memory"

    def __init__(self) -> None:
        self._rows: list[ScanRow] = []
        self._lock = threading.Lock()

    def add(self, row: ScanRow) -> None:
        with self._lock:
            self._rows.append(row)

    def get(self, scan_id: str) -> ScanRow | None:
        with self._lock:
            return next((r for r in self._rows if r.id == scan_id), None)

    def list(self, user_id: str | None, limit: int = 50) -> list[ScanRow]:
        with self._lock:
            rows = [r for r in self._rows if r.status == "done" and (user_id is None or r.user_id == user_id)]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]

    def count_since(self, since: datetime, user_id: str | None = None) -> int:
        # Scans that reached the target count towards the limits, finished or not.
        with self._lock:
            return sum(
                1
                for r in self._rows
                if r.requests_sent > 0
                and datetime.fromisoformat(r.created_at) >= since
                and (user_id is None or r.user_id == user_id)
            )

    def prune(self, before: datetime) -> None:
        with self._lock:
            self._rows = [r for r in self._rows if datetime.fromisoformat(r.created_at) >= before]


class SupabaseStore:
    """The `scans` table, through Supabase's REST API (PostgREST), with the server's secret key."""

    kind = "supabase"
    _COLUMNS = "id,user_id,user_email,target,spec_url,checks,status,requests_sent,created_at,report,error"

    def __init__(self, supabase_url: str, secret_key: str, transport: httpx.BaseTransport | None = None) -> None:
        # The secret key goes in `apikey` only; Supabase then runs the request as the service role.
        self._http = httpx.Client(
            base_url=f"{supabase_url}/rest/v1",
            headers={"apikey": secret_key},
            timeout=10,
            follow_redirects=False,
            transport=transport,
        )

    def _check(self, response: httpx.Response) -> httpx.Response:
        if response.status_code >= 300:
            # The body may echo our query; the status is enough to say what went wrong.
            raise StoreError(f"the scans table answered {response.status_code}")
        return response

    def add(self, row: ScanRow) -> None:
        self._check(self._http.post("/scans", json=asdict(row), headers={"Prefer": "return=minimal"}))

    def get(self, scan_id: str) -> ScanRow | None:
        if not is_uuid(scan_id):
            return None
        rows = self._check(self._http.get("/scans", params={"id": f"eq.{scan_id}", "select": self._COLUMNS})).json()
        return ScanRow(**rows[0]) if rows else None

    def list(self, user_id: str | None, limit: int = 50) -> list[ScanRow]:
        params = {"status": "eq.done", "order": "created_at.desc", "limit": str(limit), "select": self._COLUMNS}
        if user_id is not None:
            params["user_id"] = f"eq.{user_id}"
        return [ScanRow(**r) for r in self._check(self._http.get("/scans", params=params)).json()]

    def count_since(self, since: datetime, user_id: str | None = None) -> int:
        params = {"select": "id", "requests_sent": "gt.0", "created_at": f"gte.{since.isoformat()}"}
        if user_id is not None:
            params["user_id"] = f"eq.{user_id}"
        response = self._check(self._http.head("/scans", params=params, headers={"Prefer": "count=exact"}))
        total = response.headers.get("content-range", "").rpartition("/")[2]
        if not total.isdigit():
            raise StoreError("the scans table didn't say how many rows matched")
        return int(total)

    def prune(self, before: datetime) -> None:
        self._check(self._http.delete("/scans", params={"created_at": f"lt.{before.isoformat()}"}))
