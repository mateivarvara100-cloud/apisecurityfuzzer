"""What a check reports when it finds something: a Finding, plus the severity scale.

A Finding is deliberately plain data. A check creates it; the reporter displays it. It carries the
Exchange(s) that back it up, so a reader can see the exact request and response behind the claim.
"""

from enum import IntEnum  # an ordered set of severities, so findings can be sorted worst-first

from pydantic import BaseModel, field_serializer

from apifuzz.http_client import Exchange


class Severity(IntEnum):
    """How serious a finding is. IntEnum so `sorted(..., reverse=True)` puts the worst first."""

    INFO = 0  # not a flaw: something worth noting, or a check that confirmed good behaviour
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # so it prints as "HIGH", not "Severity.HIGH"
        return self.name


class Finding(BaseModel):
    """One result from one check about one endpoint."""

    check: str  # the id of the check that produced this, e.g. "auth-required"
    owasp: str = ""  # the OWASP API Security Top 10 category, e.g. "API1:2023 Broken Object Level Authorization"
    severity: Severity
    title: str  # a short headline, e.g. "Endpoint reachable without authentication"
    endpoint: str  # which operation, as "METHOD /path", e.g. "GET /orders/{id}"
    detail: str  # a sentence or two explaining what was observed and why it matters
    remediation: str = ""  # how a developer fixes it, in a sentence or two
    # The request/response pairs that justify the finding. Kept so a report can show evidence and
    # a reader can reproduce it. May be empty for an INFO note that isn't about a specific request.
    evidence: list[Exchange] = []

    # In JSON, write the severity as "HIGH" rather than the number 3, so reports read clearly.
    @field_serializer("severity")
    def _severity_name(self, severity: Severity) -> str:
        return severity.name
