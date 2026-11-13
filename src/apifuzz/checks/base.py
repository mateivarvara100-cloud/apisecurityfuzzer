"""The shape every security check follows, and the registry that collects them.

A check is a small class with an id, a description, and a `run` method. `run` receives one
Endpoint and a ScanContext (the HTTP client and settings it may use) and yields Findings. Checks
must send only minimal, non-destructive requests, and only through the context's client, which
enforces the host allowlist.
"""

import re  # find "{name}" placeholders in a path template
from collections.abc import Iterator  # a check yields findings, so its return type is an Iterator
from urllib.parse import quote  # make a path value safe to put in a URL

from apifuzz.endpoint_model import Endpoint
from apifuzz.finding import Finding
from apifuzz.http_client import HttpClient
from apifuzz.settings import Settings


class ScanContext:
    """Everything a check is allowed to use: the HTTP client, the settings, and the base URL.

    A check never builds its own HttpClient. It calls ctx.url(path) to turn an endpoint's path
    template into a full URL, and ctx.client.request(...) to send a request through the allowlist.
    """

    def __init__(self, client: HttpClient, settings: Settings, endpoints: list[Endpoint] | None = None) -> None:
        self.client = client
        self.settings = settings
        # Every endpoint in the scan (run_scan fills this in), so a check can do recon on others.
        self.endpoints: list[Endpoint] = endpoints or []
        # Scratch space shared across one scan, e.g. ids a check collected once and reuses.
        self.cache: dict[str, object] = {}
        # What each check did with each endpoint: {(check id, "GET /path"): (status, reason)}.
        # The report turns this into a coverage table, so "not tested" never looks like "safe".
        self.outcomes: dict[tuple[str, str], tuple[str, str]] = {}

    def record(self, check_id: str, endpoint: Endpoint, status: str, reason: str = "") -> None:
        """Note what a check did with an endpoint: TESTED, or NOT_TESTED with the reason why."""
        self.outcomes[(check_id, f"{endpoint.method} {endpoint.path}")] = (status, reason)

    def auth(self, account: str) -> dict[str, str] | None:
        """The login header for test account "a" or "b", or None if that account has no token."""
        token = self.settings.token_a if account == "a" else self.settings.token_b
        return self.settings.auth_headers(token) if token else None

    def url(self, path: str) -> str:
        """Join the base URL and an endpoint path: ("https://x", "/orders") -> "https://x/orders"."""
        return f"{self.settings.base_url}/{path.lstrip('/')}"


_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")  # matches "{id}" and captures "id"

# What a check did with an endpoint (see ScanContext.record). An endpoint a check records nothing
# for counts as "not applicable": the check has nothing to look for there.
TESTED = "tested"  # the check got a clear answer, finding or not
NOT_TESTED = "not tested"  # the check applies here but could not reach a verdict; a reason is given


def sample_value(type_label: str | None) -> str:
    """A harmless stand-in for a path parameter of the given type: "1" for numbers, else "test"."""
    return "1" if type_label in ("integer", "number") else "test"


def fill_path(endpoint: Endpoint, values: dict[str, str] | None = None) -> str:
    """Turn "/orders/{id}" into "/orders/1".

    Each placeholder takes its value from `values` if given, otherwise a sample of the right type
    (see sample_value). Values are URL-encoded, so a value can't add extra path segments.
    """
    values = values or {}
    types = {p.name: p.type for p in endpoint.parameters if p.location == "path"}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = values.get(name, sample_value(types.get(name)))
        return quote(str(value), safe="")  # safe="" also encodes "/", so it stays one segment

    return _PLACEHOLDER.sub(replace, endpoint.path)


def sample_body(endpoint: Endpoint, text: str = "test") -> dict[str, object]:
    """The smallest body the endpoint should accept: a harmless value for each required field.

    When the spec marks no field as required, every declared field is filled in instead, so the
    body is never empty. Text fields get `text`; other types get a neutral value of that type.
    """
    fields = [f for f in endpoint.request_fields if f.required] or endpoint.request_fields
    samples: dict[str, object] = {"integer": 1, "number": 1, "boolean": False, "object": {}}
    body: dict[str, object] = {}
    for field in fields:
        kind = field.type or "string"
        body[field.name] = [] if kind.startswith("array") else samples.get(kind, text)
    return body


class Check:
    """Base class for a security check. Subclasses set `id` and `description` and implement `run`.

    Subclasses are registered automatically (see __init_subclass__), so importing the checks
    package is enough for `all_checks()` to find them. `default` can be set to False for a check
    that should exist but not run unless asked for by id.
    """

    id: str = ""  # a short stable name, e.g. "auth-required"; shown in reports and --only/--skip
    owasp: str = ""  # the OWASP API Security Top 10 (2023) category the check covers
    description: str = ""  # one line explaining what the check looks for
    default: bool = True  # whether the check runs in a normal scan (vs. only when named)

    # A class-level list of every subclass, in definition order. Shared by all subclasses.
    _registry: list[type["Check"]] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Runs once for each subclass when Python defines it. We record concrete checks (those
        # that set an id); an intermediate base class without an id is skipped.
        super().__init_subclass__(**kwargs)
        if cls.id:
            Check._registry.append(cls)

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        """Yield a Finding for each problem found on `endpoint`. Yield nothing if all is well."""
        raise NotImplementedError  # every concrete check must implement this


def all_checks() -> list[type[Check]]:
    """Every registered check class, in the order they were defined."""
    return list(Check._registry)


def select_checks(only: list[str] | None = None, skip: list[str] | None = None) -> list[type[Check]]:
    """Choose which checks to run: start from the defaults (or `only`), then drop any in `skip`.

    `only` names an exact set by id (ignoring the `default` flag). `skip` removes ids from
    whatever the starting set is. Unknown ids raise KeyError so a typo is caught, not ignored.
    """
    by_id = {cls.id: cls for cls in all_checks()}
    _reject_unknown(only, by_id)
    _reject_unknown(skip, by_id)

    if only:
        chosen = [by_id[i] for i in only]
    else:
        chosen = [cls for cls in all_checks() if cls.default]

    skip_set = set(skip or [])
    return [cls for cls in chosen if cls.id not in skip_set]


def _reject_unknown(ids: list[str] | None, by_id: dict[str, type[Check]]) -> None:
    unknown = [i for i in (ids or []) if i not in by_id]
    if unknown:
        known = ", ".join(sorted(by_id)) or "(none)"
        raise KeyError(f"unknown check id: {', '.join(unknown)}. Known checks: {known}")
