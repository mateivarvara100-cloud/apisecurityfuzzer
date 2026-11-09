"""The security checks. Importing this package registers every check it contains.

To add a check: create a module here with a Check subclass, then import it below.
"""

from apifuzz.checks import auth_required, bola  # noqa: F401  (imported for their registration side effect)
from apifuzz.checks.base import Check, ScanContext, all_checks, fill_path, select_checks

__all__ = ["Check", "ScanContext", "all_checks", "fill_path", "select_checks"]
