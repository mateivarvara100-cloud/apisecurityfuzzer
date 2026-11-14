"""Check: does caller input reach a database query without being kept separate from it?

OWASP API8:2019 Injection. When an endpoint pastes a request value straight into a SQL (or
NoSQL) query instead of passing it as a bound parameter, the value can change what the query
does. A search box that builds `... LIKE '%<q>%'` by string formatting will, given a <q> that
closes the quote, run logic the caller chose instead of the logic the developer wrote.

This check DETECTS that flaw; it never uses it to read or change data. For each testable input it
sends a small set of marker values and watches the response *shape*, not its contents:

1. Error signal. One value carries a single quote (``<marker>'``). If the server answers with a
   database error (a 5xx whose body names SQL / SQLite / MySQL / Postgres / Mongo syntax), the
   quote reached a query engine without being escaped.
2. Boolean differential. Two values are sent that, pasted into a string query, are always-true
   vs. always-false (``<marker>' OR '1'='1' -- `` vs. ``<marker>' AND '1'='2' -- ``). If the
   always-true value produces a different result from the always-false one, the input is steering
   the query's logic rather than being treated as plain text.
3. NoSQL operator (body fields only). Where a scalar is expected, an operator-shaped object
   (``{"$ne": <marker>}``) is sent. If it is accepted and changes the result, the value is
   reaching a document query as structure, not data.

Each signal is confirmed on a second request before it is reported, so a one-off difference is
never a finding. The markers are inert: the check counts how many rows come back, never reads
their contents, and writes nothing.

What is probed, and what is left alone:
  * Query-string parameters on GET/HEAD endpoints.
  * JSON body fields, but only on endpoints that read or authenticate (login / search / lookup /
    query shaped). Create/update endpoints are never probed with a body, so this check cannot
    create or change data; mass-assignment covers those instead.

Severity: HIGH. A confirmed injection point is among the most serious API flaws.
"""

import json
import re
from collections.abc import Callable, Iterator

from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext, fill_path, sample_body
from apifuzz.endpoint_model import Endpoint, Parameter, RequestField
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Exchange

_MARKER = "apifuzz"  # a harmless base value no real record is expected to equal
_MAX_FIELDS = 5  # parameters/fields probed per endpoint, to keep the request count small

# Payloads appended to the marker. The trailing `-- ` comments out whatever the query puts after
# the value (a closing quote, a `%`), so the injected clause stands on its own if it is pasted in.
_QUOTE = _MARKER + "'"  # unbalanced quote: breaks a string literal and surfaces a parse error
_TRUE = _MARKER + "' OR '1'='1' -- "  # always true when pasted into a '...' context
_FALSE = _MARKER + "' AND '1'='2' -- "  # always false in the same context
_OPERATOR = {"$ne": _MARKER}  # an object where a scalar is expected: the NoSQL tell

# Statuses that mean the request was handled (so a baseline or a probe settles something). A 404
# for a sample value, or a 5xx with no database signature, settles nothing on its own.
_HANDLED = {200, 201, 202, 204, 400, 401, 403, 409, 422}

# Words (in a path segment or the operation id) that mark an endpoint whose body is a query, not
# new data: safe to probe with injection markers because nothing is created or changed.
_BODY_WORDS = {
    "login", "signin", "sign-in", "sign_in", "token", "authenticate", "auth", "session", "sessions",
    "search", "find", "lookup", "query", "filter", "suggest", "autocomplete",
}

# Words that mark a database error leaking back to the caller (matched case-insensitively).
_DB_ERROR = re.compile(
    r"sql|sqlite|mysql|mariadb|postgres|psql|oracle|odbc|syntax error|unrecognized token|"
    r"unterminated|unclosed quotation|near \"|operationalerror|programmingerror|mongo|bson",
    re.IGNORECASE,
)

_PROBEABLE_TYPES = (None, "string", "integer", "number")  # text or numbers, or a type the spec omitted


class _Unhandled:
    """What _probe returns when even a benign value was not handled, so there is nothing to
    compare a probe against. Distinct from None, which means "probed, and clean"."""


_UNHANDLED = _Unhandled()


def _sample(param_type: str | None) -> str:
    return "1" if param_type in ("integer", "number") else _MARKER


def _result_size(exchange: Exchange) -> int | None:
    """How many records the response carries, or None when it has no countable collection.

    A JSON array is counted directly; a JSON object is searched for its longest list value (for
    bodies shaped like ``{"results": [...]}``). Anything else returns None, and the caller then
    compares only status codes, never body length, so a payload echoed into the body can't be
    mistaken for a bigger result set.
    """
    try:
        body = json.loads(exchange.response.body)
    except ValueError:
        return None
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        lists = [v for v in body.values() if isinstance(v, list)]
        if lists:
            return max(len(v) for v in lists)
    return None


def _is_db_error(exchange: Exchange) -> bool:
    """True when the answer is a server error that names a database engine or a query parse error."""
    return exchange.response.status_code >= 500 and bool(_DB_ERROR.search(exchange.response.body))


def _handled(exchange: Exchange) -> bool:
    return exchange.response.status_code in _HANDLED


def _differs(a: Exchange, b: Exchange) -> bool:
    """True when two answers differ in a way that implies query logic, not just payload text.

    Preferred signal: a different number of records. Fallback: a different status code. Body
    length is deliberately not used, because the payloads are different strings and an endpoint
    that echoes its input would differ on length alone.
    """
    size_a, size_b = _result_size(a), _result_size(b)
    if size_a is not None and size_b is not None:
        return size_a != size_b
    return a.response.status_code != b.response.status_code


class Injection(Check):
    id = "injection"
    owasp = "API8:2019 Injection"
    description = "Request values must not reach a database query unescaped (SQL/NoSQL injection; detection only)."

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        headers = None
        if endpoint.requires_auth:
            headers = ctx.auth("a") or ctx.auth("b")
            if not headers:
                # Only record for endpoints this check would otherwise probe, so unrelated
                # endpoints aren't labelled "needs a test account".
                if self._query_targets(endpoint) or self._body_targets(endpoint):
                    ctx.record(self.id, endpoint, NOT_TESTED, "needs a test account")
                return

        if endpoint.method in ("GET", "HEAD"):
            yield from self._run_query(endpoint, ctx, headers)
        elif endpoint.method in ("POST", "PUT", "PATCH"):
            yield from self._run_body(endpoint, ctx, headers)

    # --- query-string parameters ---------------------------------------------------------------

    def _query_targets(self, endpoint: Endpoint) -> list[Parameter]:
        if endpoint.method not in ("GET", "HEAD"):
            return []
        return [p for p in endpoint.parameters if p.location == "query" and p.type in _PROBEABLE_TYPES]

    def _run_query(self, endpoint: Endpoint, ctx: ScanContext, headers: dict[str, str] | None) -> Iterator[Finding]:
        targets = self._query_targets(endpoint)[:_MAX_FIELDS]
        if not targets:
            return
        url = ctx.url(fill_path(endpoint))
        base = {p.name: _sample(p.type) for p in endpoint.parameters if p.location == "query" and p.required}

        tested = False
        for param in targets:
            def send(value: object, name: str = param.name) -> Exchange:
                return ctx.client.request(endpoint.method, url, headers=headers, params={**base, name: value})

            outcome = self._probe(endpoint, param.name, "query parameter", send, allow_nosql=False)
            if isinstance(outcome, _Unhandled):
                ctx.record(self.id, endpoint, NOT_TESTED, f"a benign value for {param.name!r} was not handled, which settles nothing")
                continue
            tested = True
            if outcome is not None:
                yield outcome
        if tested:
            ctx.record(self.id, endpoint, TESTED)

    # --- JSON body fields (read/auth endpoints only) -------------------------------------------

    def _body_targets(self, endpoint: Endpoint) -> list[RequestField]:
        if endpoint.method not in ("POST", "PUT", "PATCH") or not self._is_query_shaped(endpoint):
            return []
        return [f for f in endpoint.request_fields if f.type in _PROBEABLE_TYPES]

    def _is_query_shaped(self, endpoint: Endpoint) -> bool:
        words = {seg.lower() for seg in endpoint.path.split("/") if seg and "{" not in seg}
        if endpoint.operation_id:
            words |= {w.lower() for w in re.findall(r"[A-Za-z][a-z]+|[A-Z]+(?![a-z])", endpoint.operation_id)}
        return bool(words & _BODY_WORDS)

    def _run_body(self, endpoint: Endpoint, ctx: ScanContext, headers: dict[str, str] | None) -> Iterator[Finding]:
        targets = self._body_targets(endpoint)[:_MAX_FIELDS]
        if not targets:
            return
        url = ctx.url(fill_path(endpoint))
        base = sample_body(endpoint, text=_MARKER)

        tested = False
        for field in targets:
            def send(value: object, name: str = field.name) -> Exchange:
                return ctx.client.request(endpoint.method, url, headers=headers, json={**base, name: value})

            outcome = self._probe(endpoint, field.name, "body field", send, allow_nosql=True)
            if isinstance(outcome, _Unhandled):
                ctx.record(self.id, endpoint, NOT_TESTED, f"a benign value for {field.name!r} was not handled, which settles nothing")
                continue
            tested = True
            if outcome is not None:
                yield outcome
        if tested:
            ctx.record(self.id, endpoint, TESTED)

    # --- the shared decision logic -------------------------------------------------------------

    def _probe(
        self, endpoint: Endpoint, name: str, where: str, send: Callable[[object], Exchange], *, allow_nosql: bool
    ) -> Finding | _Unhandled | None:
        """Probe one input. Returns a Finding, None (clean), or _UNHANDLED (no usable baseline)."""
        baseline = send(_MARKER)
        if not _handled(baseline):
            return _UNHANDLED

        # 1) Error-based: an unbalanced quote that produces a database error, confirmed on a repeat.
        quote = send(_QUOTE)
        if _is_db_error(quote) and _is_db_error(send(_QUOTE)):
            return self._finding(
                endpoint, name, where, how="a database error",
                detail=(
                    f"Sending the {where} {name!r} as {_QUOTE!r} (a value with one extra quote) was answered "
                    f"HTTP {quote.response.status_code} with a database error in the body, confirmed on a second "
                    "request. The quote reached the query engine unescaped, so the value is placed into the query "
                    "text rather than bound as a parameter."
                ),
                evidence=[baseline, quote],
            )

        # 2) Boolean differential: always-true vs. always-false, each confirmed on a repeat.
        true1, false1 = send(_TRUE), send(_FALSE)
        if _handled(true1) and _handled(false1) and _differs(true1, false1):
            true2, false2 = send(_TRUE), send(_FALSE)
            if _result_size(true2) == _result_size(true1) and _result_size(false2) == _result_size(false1) and _differs(true2, false2):
                return self._finding(
                    endpoint, name, where, how="a boolean differential",
                    detail=(
                        f"An always-true value for the {where} {name!r} ({_TRUE!r}) and an always-false value "
                        f"({_FALSE!r}) were answered differently, and the difference repeated on a second pair of "
                        "requests. A value treated as plain text would give the same answer both times; a different "
                        "answer means the value is changing what the query selects."
                    ),
                    evidence=[true1, false1],
                )

        # 3) NoSQL operator object where a scalar is expected (body fields only).
        if allow_nosql:
            op1 = send(_OPERATOR)
            if _handled(op1) and _differs(op1, baseline):
                op2 = send(_OPERATOR)
                if _result_size(op2) == _result_size(op1) and _differs(op2, baseline):
                    return self._finding(
                        endpoint, name, where, how="a NoSQL operator object",
                        detail=(
                            f"Sending the {where} {name!r} as the operator object {_OPERATOR!r}, where a plain value "
                            "is expected, changed the response compared with a plain value, and the change repeated. "
                            "The object is being interpreted as part of a document query rather than rejected as the "
                            "wrong type, which is how NoSQL operator injection works."
                        ),
                        evidence=[baseline, op1],
                    )
        return None

    def _finding(
        self, endpoint: Endpoint, name: str, where: str, *, how: str, detail: str, evidence: list[Exchange]
    ) -> Finding:
        return Finding(
            check=self.id,
            owasp=self.owasp,
            severity=Severity.HIGH,
            title=f"{where.capitalize()} {name!r} reaches a database query unsafely (injection)",
            endpoint=f"{endpoint.method} {endpoint.path}",
            key=name,
            detail=detail + f" This was detected by {how}; no data was read or changed.",
            remediation=(
                "Never build a query by pasting request values into its text. Use parameterized queries (bound "
                "placeholders) or your data layer's query builder, so input is always sent as data, not as part of "
                "the query. For NoSQL, reject operator-shaped objects where a scalar is expected, and validate the "
                "type and range of every value. Do not return raw database errors to the caller."
            ),
            evidence=evidence,
        )

