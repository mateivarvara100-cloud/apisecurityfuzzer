"""Check: does an endpoint that the spec says needs a login actually refuse anonymous callers?

This is OWASP API2 (Broken Authentication) in its simplest form. It sends one request per
endpoint with no credentials, plus a second one to confirm when the first succeeds, and only for
read-only methods (GET/HEAD), so it cannot change any data on the target.
"""

from collections.abc import Iterator

from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext, fill_path
from apifuzz.endpoint_model import Endpoint
from apifuzz.finding import Finding, Severity

# Methods that by HTTP's own rules must not change server state. Anything else is skipped here,
# because an unauthenticated POST/DELETE that *succeeded* would have done real damage.
_SAFE_METHODS = {"GET", "HEAD"}


class AuthRequired(Check):
    id = "auth-required"
    owasp = "API2:2023 Broken Authentication"
    description = "Endpoints the spec marks as needing a login must reject a request with no credentials."

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        if not endpoint.requires_auth or endpoint.method not in _SAFE_METHODS:
            return  # nothing to check: open by design, or not safe to probe this way

        # No headers at all: in particular, no credentials.
        url = ctx.url(fill_path(endpoint))
        exchange = ctx.client.request(endpoint.method, url)
        status = exchange.response.status_code

        # Only a success counts as a finding. 401/403 is the correct answer. Anything else (a 404
        # for a missing sample object, a 5xx from a broken route) means we can't tell, so we stay
        # quiet rather than guess, and the report says the endpoint was not tested.
        if status in (401, 403):
            ctx.record(self.id, endpoint, TESTED)
            return
        if not exchange.response.ok:
            ctx.record(self.id, endpoint, NOT_TESTED, f"answered HTTP {status} to the sample request, which settles nothing")
            return
        ctx.record(self.id, endpoint, TESTED)
        # Confirmation: the same request again. Only a reproducible result is reported.
        confirm = ctx.client.request(endpoint.method, url)
        if confirm.response.ok:
            yield Finding(
                check=self.id,
                owasp=self.owasp,
                severity=Severity.HIGH,
                title="Endpoint answers without authentication",
                endpoint=f"{endpoint.method} {endpoint.path}",
                detail=(
                    f"The spec says this endpoint requires a login, but a request with no "
                    f"credentials got HTTP {status} (confirmed on a second request). Anyone may be "
                    f"able to call it."
                ),
                remediation=(
                    "Require a valid login on this route (for example with your framework's auth "
                    "middleware or dependency) and answer 401 when the credentials are missing."
                ),
                evidence=[exchange, confirm],
            )
