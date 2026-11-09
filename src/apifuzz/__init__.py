"""apifuzz: an OpenAPI-driven security scanner for authorized staging APIs."""

# This file makes the folder "apifuzz" a Python package (so `import apifuzz.cli` works).
# It also exposes __version__, which `apifuzz --version` prints.

from importlib.metadata import PackageNotFoundError, version

try:
    # Read the version from the installed package metadata, which comes from pyproject.toml.
    # This way the version number is written in exactly one place.
    __version__ = version("apifuzz")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0"
