"""Protection for the HTTP layer itself: request rate limits, a body size cap, security headers.

These sit in front of every route. The per-day scan limits are separate (in app.py); these stop
someone hammering the API with cheap requests, or sending a huge body to tie up the server.
"""

import json
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.exceptions import HTTPException

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class RateLimiter:
    """At most `limit` hits per key in any `window` seconds (a sliding window). In memory.

    One server process holds all the state, which fits a single free-tier instance. Keys that go
    quiet are dropped, and the number of keys is capped so the table can't be grown without end.
    """

    def __init__(self, limit: int, window: float, max_keys: int = 10_000) -> None:
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> float | None:
        """Record a hit. None if allowed, else the seconds until the next hit would be."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    self._sweep(now)
                hits = self._hits[key] = deque()
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(0.0, hits[0] + self.window - now)
            hits.append(now)
            return None

    def _sweep(self, now: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= now - self.window]:
            del self._hits[key]
        if len(self._hits) >= self.max_keys:  # still full: everyone is active, start over
            self._hits.clear()


def client_ip(scope: Scope, behind_proxy: bool) -> str:
    """The caller's address. Behind a proxy (Render), the last X-Forwarded-For entry.

    The proxy appends the address it saw, so the last entry is the one a caller can't forge;
    earlier entries are whatever the caller sent. Without a proxy the header is ignored.
    """
    if behind_proxy:
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                last = value.decode("latin-1").rsplit(",", 1)[-1].strip()
                if last:
                    return last
    client = scope.get("client")
    return client[0] if client else "unknown"


SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),  # answers carry scan reports: never cache them
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-resource-policy", b"same-site"),
]


class Guards:
    """ASGI middleware: per-IP rate limit, body size cap, security headers on every answer."""

    def __init__(
        self, app: ASGIApp, *, ip_limiter: RateLimiter, max_body: int = 16_384, behind_proxy: bool = False
    ) -> None:
        self.app, self.ip_limiter, self.max_body, self.behind_proxy = app, ip_limiter, max_body, behind_proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + SECURITY_HEADERS
            await send(message)

        # Preflight requests are answered by the CORS layer and don't count against the limit.
        if scope["method"] != "OPTIONS":
            wait = self.ip_limiter.hit(client_ip(scope, self.behind_proxy))
            if wait is not None:
                await _reply(send_with_headers, 429, "Too many requests. Wait a moment and try again.", wait)
                return

        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_body):
            await _reply(send_with_headers, 413, "The request is too large.")
            return

        # A body sent without a length (chunked) is counted as it arrives.
        received = 0

        async def capped_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    # Raised inside the route's body parsing, so FastAPI turns it into a 413 answer.
                    raise HTTPException(413, "The request is too large.")
            return message

        await self.app(scope, capped_receive, send_with_headers)


async def _reply(send: Send, status: int, detail: str, retry_after: float | None = None) -> None:
    body = json.dumps({"detail": detail}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    if retry_after is not None:
        headers.append((b"retry-after", str(max(1, round(retry_after))).encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
