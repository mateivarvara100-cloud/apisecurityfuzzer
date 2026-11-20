"""The only place apifuzz sends requests to a target.

Every request is checked against an allowlist before it leaves the process, and the raw request
and response are recorded so a finding can later show its evidence.
"""

import threading  # the rate-limit check may send a burst from several threads at once
import time  # used to measure how long each request took
from collections.abc import Callable, Iterable  # type hints: a function value, "anything you can loop over"
from types import TracebackType  # type hint used by __exit__ (the `with` statement support)
from typing import Any
from urllib.parse import urlparse  # splits a URL into scheme, host, port, path...

import httpx  # the HTTP library that actually sends requests
from pydantic import BaseModel  # typed record classes with free JSON output

from apifuzz import __version__
from apifuzz.errors import AllowlistError, RequestError, RequestLimitError

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


class Credentials(dict[str, str]):
    """How one test account logs a request in: the headers to send, plus any query-string values.

    It is a dict of headers, so it can be passed straight to `HttpClient.request(headers=...)`.
    An API that takes its key in the query string (`?api_key=...`) gets an empty header dict and
    the key in `params`; the client adds those to the URL. `account` ("a" / "b") and `token` let
    the client ask for a fresh login when the token stops working in the middle of a scan.
    """

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        *,
        params: dict[str, str] | None = None,
        account: str | None = None,
        token: str | None = None,
    ) -> None:
        super().__init__(headers or {})
        self.params = dict(params or {})
        self.account = account
        self.token = token

    def __bool__(self) -> bool:
        # A query-string key has no headers, but it is still a login.
        return bool(len(self) or self.params)

    def merged(self, extra: dict[str, str]) -> "Credentials":
        """These credentials with extra headers added (e.g. a header the endpoint requires)."""
        return Credentials({**self, **extra}, params=self.params, account=self.account, token=self.token)


# Called with the credentials of a request that was answered 401. Returns fresh credentials to
# retry once with, or None to keep the 401 as the answer.
Reauthenticate = Callable[[Credentials], "Credentials | None"]


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
        max_requests: int | None = None,  # stop the scan after this many requests (None = no cap)
        delay: float = 0.0,  # seconds to wait between requests, to go easy on the target
    ) -> None:
        self._allowlist = allowlist
        self._max_body_bytes = max_body_bytes
        self._max_requests = max_requests
        self._delay = delay
        self.requests_sent = 0  # requests that left the process (whether or not they were answered)
        self.responses_received = 0  # requests that got an HTTP answer back
        # Set by the CLI once the test accounts are logged in: a way to log in again when a token
        # expires mid-scan (see session_manager.Reauthenticator). None means a 401 is final.
        self.reauthenticate: Reauthenticate | None = None
        self._lock = threading.Lock()  # guards the counters and the delay when threads share the client
        # One reusable httpx client: it keeps connections open between requests (faster).
        # The User-Agent names the tool, so the target's logs show where the traffic came from.
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": f"apifuzz/{__version__}"},
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,  # e.g. {"Authorization": "Bearer <token>"}
        params: dict[str, Any] | None = None,  # query string values, e.g. {"q": "book"}
        json: Any = None,  # a body to send as JSON
        data: dict[str, str] | None = None,  # a body to send as form fields (some logins need this)
        refresh: bool = True,  # on a 401, may the client log the account in again and retry once?
    ) -> Exchange:
        exchange = self._send(method, url, headers=headers, params=params, json=json, data=data)
        if (
            refresh
            and exchange.response.status_code == 401
            and self.reauthenticate is not None
            and isinstance(headers, Credentials)
            and headers.account
        ):
            fresh = self.reauthenticate(headers)
            if fresh is not None:
                # One retry with the new token. Its answer is the one the check sees.
                return self._send(method, url, headers=fresh, params=params, json=json, data=data)
        return exchange

    def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        params: dict[str, Any] | None,
        json: Any,
        data: dict[str, str] | None,
    ) -> Exchange:
        if isinstance(headers, Credentials) and headers.params:
            params = {**(params or {}), **headers.params}  # an API key that goes in the query string
        # httpx's `params=` REPLACES a query string already in the URL ("/search?q=a" would lose
        # q=a). Merge instead, so a URL from the spec or the user keeps its own query values.
        full_url = httpx.URL(url).copy_merge_params(params) if params else url
        # Build the request without sending it, so we can inspect the final URL first.
        request = self._client.build_request(
            method, full_url, headers=dict(headers) if headers else None, json=json, data=data
        )
        self._allowlist.check(str(request.url))  # before anything is sent
        with self._lock:  # several threads may share this client during a concurrent burst
            if self._max_requests is not None and self.requests_sent >= self._max_requests:
                raise RequestLimitError(f"request limit reached ({self._max_requests}); raise it with --max-requests")
            if self._delay and self.requests_sent:
                time.sleep(self._delay)
            self.requests_sent += 1

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
        with self._lock:
            self.responses_received += 1

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
