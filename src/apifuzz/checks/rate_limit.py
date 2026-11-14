"""Check: does an endpoint that invites repeated attempts limit how often it can be called?

This is OWASP API4 (Unrestricted Resource Consumption). A login endpoint with no limit lets
someone try passwords all day; an unlimited search endpoint can be used to run up cost.

The check sends a small, fixed number of identical requests (the "burst", 15 by default, never
more than 50) one after another and watches for any sign of throttling:

- an HTTP 429 (Too Many Requests) answer, or
- a Retry-After, RateLimit-* or X-RateLimit-* header on any answer, or
- a clear slowdown: the last third of the burst is answered several times slower than the
  first third (some APIs delay repeated attempts instead of refusing them).

It stops at the first sign. If the whole burst is answered with none, the endpoint is reported.
This is detection, not a load test: the requests are sequential and the burst is capped.

Which endpoints are tried, and how:
  login-like POST   (login, signin, token, auth, session...)  HIGH
      Sent with made-up credentials for a user that doesn't exist, so every attempt is a failed
      login. Nothing is created and no real account can be locked out.
  search-like GET   (search, find, lookup, suggest...)        MEDIUM
      Sent with a harmless sample value for each required query parameter.

Endpoints that create data or send messages (sign-up, password reset, "send") are never burst,
even though they also need rate limits: fifteen sign-ups or reset e-mails are not harmless.
"""

import re
import time
from collections.abc import Iterator

from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext, fill_path, sample_body
from apifuzz.endpoint_model import Endpoint
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Exchange

MAX_BURST = 50  # hard ceiling, whatever the setting says
# Words (in a path segment or the operation id) that mark the two kinds of endpoint tried.
_LOGIN_WORDS = {"login", "signin", "sign-in", "sign_in", "token", "authenticate", "auth", "session", "sessions"}
_SEARCH_WORDS = {"search", "find", "lookup", "autocomplete", "suggest", "query"}
# Answers that show the request was handled normally. Anything else (404, 405, 5xx) says the
# probe itself was wrong or the route is broken, which settles nothing about throttling.
_HANDLED = {200, 201, 202, 204, 400, 401, 403, 422}
_PROBE_USER = "apifuzz-rate-limit-probe"  # a username that should not exist on the target


def _words(endpoint: Endpoint) -> set[str]:
    # "/api/v1/auth/login" -> {"api", "v1", "auth", "login"}, plus the operation id's words.
    words = {segment.lower() for segment in endpoint.path.split("/") if segment and "{" not in segment}
    if endpoint.operation_id:
        # "searchProducts" -> search, products; "list_orders" -> list, orders
        words |= {w.lower() for w in re.findall(r"[A-Za-z][a-z]+|[A-Z]+(?![a-z])", endpoint.operation_id)}
    return words


def kind_of(endpoint: Endpoint) -> str | None:
    """ "login", "search", or None when the check leaves the endpoint alone."""
    words = _words(endpoint)
    if endpoint.method == "POST" and words & _LOGIN_WORDS:
        return "login"
    if endpoint.method == "GET" and words & _SEARCH_WORDS:
        return "search"
    return None


def _throttle_sign(exchange: Exchange) -> str | None:
    """What in this answer shows rate limiting, e.g. "HTTP 429" or "a RateLimit-Limit header"."""
    if exchange.response.status_code == 429:
        return "HTTP 429"
    for name in exchange.response.headers:
        lower = name.lower()
        if lower == "retry-after" or lower.startswith(("ratelimit", "x-ratelimit", "x-rate-limit")):
            return f"a {name} header"
    return None


def _slowed_down(timings: list[float]) -> bool:
    """True if the last third of the burst took several times longer than the first third.

    Needs both a big ratio (5x) and a big absolute gap (half a second), so ordinary jitter on a
    fast endpoint is not mistaken for throttling.
    """
    third = len(timings) // 3
    if third < 1:
        return False
    early = sorted(timings[:third])[third // 2]  # the median of each third
    late = sorted(timings[-third:])[third // 2]
    return late >= 5 * early and late - early >= 500


class RateLimit(Check):
    id = "rate-limit"
    owasp = "API4:2023 Unrestricted Resource Consumption"
    description = "Login and search endpoints must limit repeated requests (answers 429 or sends rate-limit headers)."

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        kind = kind_of(endpoint)
        if kind is None:
            return
        headers = None
        if endpoint.requires_auth:
            headers = ctx.auth("a") or ctx.auth("b")
            if not headers:
                ctx.record(self.id, endpoint, NOT_TESTED, "needs a test account")
                return

        url = ctx.url(fill_path(endpoint))
        body = None
        params = None
        if kind == "login":
            # Made-up credentials: text fields get the probe user name, so each attempt just fails.
            body = sample_body(endpoint, text=_PROBE_USER)
        else:
            params = {p.name: "1" if p.type in ("integer", "number") else "test"
                      for p in endpoint.parameters if p.location == "query" and p.required}

        burst = max(2, min(ctx.settings.burst, MAX_BURST))
        sent: list[Exchange] = []
        timings: list[float] = []
        started = time.perf_counter()
        for _ in range(burst):
            last = ctx.client.request(endpoint.method, url, headers=headers, params=params or None, json=body)
            sent.append(last)
            timings.append(last.elapsed_ms)
            sign = _throttle_sign(last)
            if sign:
                ctx.record(self.id, endpoint, TESTED)  # throttled: the endpoint is doing its job
                return
            if last.response.status_code not in _HANDLED:
                ctx.record(
                    self.id, endpoint, NOT_TESTED,
                    f"answered HTTP {last.response.status_code} to the probe request, which settles nothing",
                )
                return

        ctx.record(self.id, endpoint, TESTED)
        if _slowed_down(timings):
            return  # answers got much slower as the burst went on: the endpoint delays repeats
        seconds = time.perf_counter() - started
        first, last = sent[0], sent[-1]
        statuses = f"HTTP {first.response.status_code}"
        if kind == "login":
            severity, title = Severity.HIGH, "Login endpoint has no rate limit"
            risk = "Someone can try passwords against it without being slowed down (brute force, credential stuffing)."
            fix = (
                "Limit attempts per account and per client address (for example 5 a minute), answer 429 "
                "with a Retry-After header once the limit is hit, and consider a growing delay or a "
                "temporary lock after repeated failures."
            )
        else:
            severity, title = Severity.MEDIUM, "Search endpoint has no rate limit"
            risk = "Someone can call it in a loop to scrape data or run up cost."
            fix = (
                "Limit requests per client (per token or address), answer 429 with a Retry-After header "
                "once the limit is hit, and cap how much one request can return."
            )
        yield Finding(
            check=self.id,
            owasp=self.owasp,
            severity=severity,
            title=title,
            endpoint=f"{endpoint.method} {endpoint.path}",
            detail=(
                f"{burst} identical requests in a row ({seconds:.1f} s) were all answered ({statuses} first, "
                f"HTTP {last.response.status_code} last) with no 429 and no rate-limit header. {risk}"
            ),
            remediation=fix,
            evidence=[first, last],  # the first and the last of the burst; the ones between look the same
        )
