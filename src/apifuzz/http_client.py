"""The only place apifuzz sends requests to a target.

Every request is checked against an allowlist before it leaves the process, and the raw request
and response are recorded so a finding can later show its evidence.
"""

import time  # used to measure how long each request took
from collections.abc import Iterable  # type hint for "anything you can loop over"
from types import TracebackType  # type hint used by __exit__ (the `with` statement support)
from typing import Any
from urllib.parse import urlparse  # splits a URL into scheme, host, port, path...

import httpx  # the HTTP library that actually sends requests
from pydantic import BaseModel  # typed record classes with free JSON output

from apifuzz.errors import AllowlistError, RequestError

# The only schemes we allow, and the port each one uses when the URL doesn't name a port.
DEFAULT_PORTS = {"http": 80, "https": 443}


class Allowlist:
    """Hosts the tool may talk to. Entries are `host` (any port) or `host:port`.

    Matching is exact on the host name: allowing `example.com` does not allow `api.example.com`.
    An empty allowlist permits nothing.
    """

    def __init__(self, entries: Iterable[str] = ()) -> None:
        # Stored as (host, port) pairs; port None means "any port on this host".
        # A set makes duplicates disappear and lookups fast.
        self._entries: set[tuple[str, int | None]] = set()
        for entry in entries:
            self._entries.add(self._parse_entry(entry))

    @staticmethod  # doesn't need `self`; it's a helper that belongs with this class
    def _parse_entry(entry: str) -> tuple[str, int | None]:
        text = entry.strip()
        # urlparse only recognises a host when it follows "//". A bare entry like "localhost:8000"
        # would be misread as a path, so we put "//" in front. Full URLs already have "://".
        parsed = urlparse(text if "://" in text else f"//{text}")
        try:
            # .hostname is lower-cased and has [ ] removed from IPv6 addresses.
            # .port raises ValueError for a non-number like "localhost:abc".
            host, port = parsed.hostname, parsed.port
        except ValueError:
            host, port = None, None
        if not host:
            # A bad entry is a configuration mistake: fail loudly rather than allow nothing silently.
            raise ValueError(f"invalid allowlist entry: {entry!r}")
        return host, port

    def permits(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            # Using .hostname (not the raw text) defeats tricks like "http://allowed.com@evil.test/":
            # the part before "@" is a username, and the real host is evil.test.
            host, port = parsed.hostname, parsed.port
        except ValueError:
            return False  # unparseable URL: refuse
        if parsed.scheme not in DEFAULT_PORTS or not host:
            return False  # only http(s) with a real host; no file://, ftp://, etc.
        port = port or DEFAULT_PORTS[parsed.scheme]  # no port in the URL -> 80 or 443
        # Allowed if ANY entry has the same host and either no port restriction or the same port.
        return any(host == allowed_host and allowed_port in (None, port) for allowed_host, allowed_port in self._entries)

    def check(self, url: str) -> None:
        # Same test as permits(), but raises instead of returning False, so callers can't
        # forget to look at the answer.
        if not self.permits(url):
            raise AllowlistError(f"refusing to contact {url}: its host is not on the allowlist")


# The three record classes below are the "evidence" a finding will show in a report.


class RecordedRequest(BaseModel):
    method: str  # "GET", "POST"...
    url: str  # the full URL as sent, query string included
    headers: dict[str, str]  # every header sent, including Authorization
    body: str | None = None  # None for requests without a body (a GET, usually)


class RecordedResponse(BaseModel):
    status_code: int  # 200, 403, 404...
    headers: dict[str, str]
    body: str  # the body as text, cut off at the capture limit
    truncated: bool = False  # True when the body was longer than the capture limit

    @property
    def ok(self) -> bool:
        """True for a 2xx status: the request succeeded."""
        return 200 <= self.status_code < 300


class Exchange(BaseModel):
    """One request and the response it got, as sent and received."""

    request: RecordedRequest
    response: RecordedResponse
    elapsed_ms: float  # how long the round trip took (useful later for the rate-limit check)


class HttpClient:
    """Sends requests to allowlisted hosts and returns them as Exchange records.

    Redirects are never followed: a redirect could point at a host outside the allowlist, so the
    3xx response is returned as it is. Request headers (including Authorization) are recorded
    unredacted; redaction belongs to the reporter.
    """

    def __init__(
        self,
        allowlist: Allowlist,
        *,  # everything after this must be passed by name, e.g. timeout=5
        timeout: float = 10.0,  # seconds before a request is abandoned
        max_body_bytes: int = 64 * 1024,  # keep at most 64 KB of each response body
        transport: httpx.BaseTransport | None = None,  # tests pass a fake network here
    ) -> None:
        self._allowlist = allowlist
        self._max_body_bytes = max_body_bytes
        # One reusable httpx client: it keeps connections open between requests (faster).
        self._client = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,  # e.g. {"Authorization": "Bearer <token>"}
        params: dict[str, Any] | None = None,  # query string values, e.g. {"q": "book"}
        json: Any = None,  # a body to send as JSON
    ) -> Exchange:
        # httpx's `params=` REPLACES a query string already in the URL ("/search?q=a" would lose
        # q=a). Merge instead, so a URL from the spec or the user keeps its own query values.
        full_url = httpx.URL(url).copy_merge_params(params) if params else url
        # Build the request without sending it, so we can inspect the final URL first.
        request = self._client.build_request(method, full_url, headers=headers, json=json)
        self._allowlist.check(str(request.url))  # before anything is sent

        started = time.perf_counter()  # a high-precision clock, good for measuring durations
        try:
            # stream=True means "don't download the whole body yet"; we read it ourselves below
            # so we can stop at the size limit instead of loading a huge response into memory.
            response = self._client.send(request, stream=True)
            try:
                body, truncated = self._read_body(response)
            finally:
                response.close()  # always release the connection, even if reading failed
        except httpx.HTTPError as exc:
            # Network-level failure (refused, timed out...). Convert it to our own error type.
            # `exc or type(exc).__name__`: some httpx errors have an empty message; fall back to the class name.
            raise RequestError(f"{method.upper()} {request.url}: {exc or type(exc).__name__}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000  # seconds -> milliseconds

        # Package everything into plain records that a report can show later.
        return Exchange(
            request=RecordedRequest(
                method=request.method,
                url=str(request.url),
                headers=dict(request.headers),
                # request.content is raw bytes; decode to text. errors="replace" swaps any bytes
                # that aren't valid UTF-8 for a placeholder character instead of crashing.
                body=request.content.decode("utf-8", errors="replace") if request.content else None,
            ),
            response=RecordedResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body,
                truncated=truncated,
            ),
            elapsed_ms=elapsed_ms,
        )

    def _read_body(self, response: httpx.Response) -> tuple[str, bool]:
        # Read the body in chunks and stop once we have more than the limit.
        received = bytearray()  # a growable byte buffer
        for chunk in response.iter_bytes():
            received += chunk
            if len(received) > self._max_body_bytes:
                break
        # "More than the limit" (not "equal to") means something was actually cut off.
        truncated = len(received) > self._max_body_bytes
        return bytes(received[: self._max_body_bytes]).decode("utf-8", errors="replace"), truncated

    def close(self) -> None:
        self._client.close()  # close the open connections

    # __enter__ and __exit__ let you write `with HttpClient(...) as client:`.
    # The client is then closed automatically when the `with` block ends, even after an error.

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
