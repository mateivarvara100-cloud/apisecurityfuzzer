"""The security checks. Importing this package registers every check it contains.

To add a check: create a module here with a Check subclass, then import it below.
"""

from apifuzz.checks import auth_required, bola, mass_assignment, rate_limit  # noqa: F401  (imported for their registration side effect)
from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext, all_checks, fill_path, select_checks

__all__ = ["NOT_TESTED", "TESTED", "Check", "ScanContext", "all_checks", "fill_path", "select_checks"]
