# Tests for the `apifuzz` command, run in-process with typer's CliRunner.

import json

from typer.testing import CliRunner

from apifuzz import __version__
from apifuzz.cli import app

runner = CliRunner()


# `apifuzz --version` prints the version and exits successfully.
def test_version():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"apifuzz {__version__}"


# `--json` output lists the six sample endpoints with the right login flags.
def test_endpoints_json_lists_the_sample_endpoints(sample_spec_path):
    result = runner.invoke(app, ["endpoints", str(sample_spec_path), "--json"])

    assert result.exit_code == 0
    found = {(e["method"], e["path"]): e for e in json.loads(result.stdout)}
    assert set(found) == {
        ("POST", "/login"),
        ("GET", "/me"),
        ("POST", "/orders"),
        ("GET", "/orders/{id}"),
        ("PATCH", "/users/{id}"),
        ("GET", "/search"),
    }
    assert found[("GET", "/me")]["requires_auth"] is True
    assert found[("POST", "/login")]["requires_auth"] is False


# The table output contains every route and the endpoint count.
def test_endpoints_table_shows_every_route(sample_spec_path):
    result = runner.invoke(app, ["endpoints", str(sample_spec_path)])

    assert result.exit_code == 0
    for route in ("/login", "/me", "/orders", "/orders/{id}", "/users/{id}", "/search"):
        assert route in result.stdout
    assert "6 endpoints" in result.stdout


# The --i-have-authorization flag is accepted without breaking anything.
def test_authorization_flag_is_accepted(sample_spec_path):
    result = runner.invoke(app, ["endpoints", str(sample_spec_path), "--i-have-authorization", "--json"])

    assert result.exit_code == 0


# An invalid spec exits with code 2, prints an "error:" line, and shows no traceback.
def test_broken_spec_exits_2_with_a_clear_message(write_spec):
    result = runner.invoke(app, ["endpoints", write_spec({"openapi": "3.0.3", "paths": {}})])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "error:" in result.output
    assert "Traceback" not in result.output


# A missing spec file exits with code 2 and says "file not found".
def test_missing_file_exits_2():
    result = runner.invoke(app, ["endpoints", "nope.json"])

    assert result.exit_code == 2
    assert "file not found" in result.output
