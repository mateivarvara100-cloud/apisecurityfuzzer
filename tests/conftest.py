# Shared test helpers. pytest loads this file automatically and makes its fixtures available
# to every test file in this folder.

import json
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"


# Gives a test the path to the VulnShop-shaped sample spec in tests/data/.
@pytest.fixture
def sample_spec_path() -> Path:
    return DATA / "sample_openapi.json"


# Gives a test a function that writes a spec to a temporary file and returns its path.
@pytest.fixture
def write_spec(tmp_path):
    """Write a spec (dict -> JSON, str -> as-is) to a temp file and return its path as a string."""

    def _write(content, name: str = "spec.json") -> str:
        path = tmp_path / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return str(path)

    return _write


# Builds the smallest valid OpenAPI 3 spec; tests pass keyword arguments to add or replace parts.
def minimal_spec(**overrides) -> dict:
    spec = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}}
    spec.update(overrides)
    return spec
