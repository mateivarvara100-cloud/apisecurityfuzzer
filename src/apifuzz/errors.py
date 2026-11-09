"""Exceptions raised by apifuzz. The CLI turns any ApifuzzError into a one-line message."""

# Why custom exception classes? They let the CLI tell "expected problems" (bad spec, blocked
# host) apart from real bugs. The CLI catches ApifuzzError and prints a friendly message;
# any other exception is a bug and is allowed to show a full traceback.


class ApifuzzError(Exception):
    """Base class for errors that are safe to show to the user as-is."""


# Each subclass below inherits from ApifuzzError, so `except ApifuzzError` catches all of them,
# while code that cares about one specific problem can catch just that subclass.


class SpecError(ApifuzzError):
    """The OpenAPI spec could not be read, parsed, resolved or validated."""


class AllowlistError(ApifuzzError):
    """A request was refused because its target is not on the allowlist."""


class DockerVerifyError(ApifuzzError):
    """--require-docker is on, and the target couldn't be confirmed as a running Docker container."""


class RequestError(ApifuzzError):
    """A request to an allowed target failed at the network level (refused, timed out...)."""


class SessionError(ApifuzzError):
    """Logging in a test account failed (bad credentials, no login endpoint, no token in the answer)."""
