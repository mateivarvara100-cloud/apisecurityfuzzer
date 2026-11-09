# Tests for the `apifuzz endpoints` filter options (--method, --path, --tag, --auth), the table
# caption, markup safety, and the ways of starting the program.

import json
import subprocess
import sys

from typer.testing import CliRunner

from apifuzz import __version__
from apifuzz.cli import app
from conftest import minimal_spec

runner = CliRunner()


# Helper: a valid OpenAPI 3.0 operation (it must list at least one response) with extra keys.
def op(**extra) -> dict:
    return {"responses": {"200": {"description": "ok"}}, **extra}


# Helper: run `apifuzz endpoints <spec> --json <extra...>` and return the (method, path) pairs.
def _listed(spec_path, *extra) -> set[tuple[str, str]]:
    result = runner.invoke(app, ["endpoints", str(spec_path), "--json", *extra])
    assert result.exit_code == 0, result.output
    return {(e["method"], e["path"]) for e in json.loads(result.stdout)}


# --method keeps only that method, ignores case, and can be repeated.
def test_method_filter(sample_spec_path):
    assert _listed(sample_spec_path, "-m", "post") == {("POST", "/login"), ("POST", "/orders")}
    assert _listed(sample_spec_path, "-m", "PATCH", "-m", "get") == {
        ("GET", "/me"),
        ("GET", "/orders/{id}"),
        ("PATCH", "/users/{id}"),
        ("GET", "/search"),
    }


# An unknown method is a usage error (exit 2), caught before the spec is even read.
def test_unknown_method_is_a_usage_error():
    result = runner.invoke(app, ["endpoints", "nope.json", "-m", "FETCH"])

    assert result.exit_code == 2
    assert "FETCH" in result.output
    assert "file not found" not in result.output


# --path takes a shell-style pattern, matched against the whole path with case mattering.
def test_path_filter(sample_spec_path):
    assert _listed(sample_spec_path, "--path", "/orders*") == {("POST", "/orders"), ("GET", "/orders/{id}")}
    assert _listed(sample_spec_path, "-p", "*{id}") == {("GET", "/orders/{id}"), ("PATCH", "/users/{id}")}
    assert _listed(sample_spec_path, "--path", "/ME") == set()


# --auth login / --auth none split the endpoints by whether they need a login.
def test_auth_filter(sample_spec_path):
    assert _listed(sample_spec_path, "--auth", "none") == {("POST", "/login"), ("GET", "/search")}
    assert _listed(sample_spec_path, "--auth", "login") == {
        ("GET", "/me"),
        ("POST", "/orders"),
        ("GET", "/orders/{id}"),
        ("PATCH", "/users/{id}"),
    }


# --auth only accepts login or none.
def test_auth_filter_rejects_other_values(sample_spec_path):
    assert runner.invoke(app, ["endpoints", str(sample_spec_path), "--auth", "maybe"]).exit_code == 2


# Several filters together must all match.
def test_filters_combine(sample_spec_path):
    assert _listed(sample_spec_path, "-m", "GET", "--auth", "login", "-p", "/orders*") == {("GET", "/orders/{id}")}


# --tag keeps endpoints carrying any of the given tags.
def test_tag_filter(write_spec):
    spec = minimal_spec(
        paths={
            "/a": {"get": op(tags=["orders"])},
            "/b": {"get": op(tags=["users", "admin"])},
            "/c": {"get": op()},
        }
    )
    path = write_spec(spec)

    assert _listed(path, "--tag", "admin") == {("GET", "/b")}
    assert _listed(path, "-t", "orders", "-t", "admin") == {("GET", "/a"), ("GET", "/b")}
    assert _listed(path, "--tag", "nothing") == set()


# The JSON output includes tags and the deprecated flag.
def test_json_includes_tags_and_deprecated(write_spec):
    path = write_spec(minimal_spec(paths={"/old": {"get": op(tags=["legacy"], deprecated=True)}}))

    (endpoint,) = json.loads(runner.invoke(app, ["endpoints", path, "--json"]).stdout)

    assert endpoint["tags"] == ["legacy"]
    assert endpoint["deprecated"] is True


# When a filter hides endpoints, the caption says "N of TOTAL".
def test_filtered_table_caption_shows_the_total(sample_spec_path):
    result = runner.invoke(app, ["endpoints", str(sample_spec_path), "-m", "POST"])

    assert "2 of 6 endpoints" in result.stdout


# One endpoint is "1 endpoint", not "1 endpoints".
def test_caption_uses_singular_for_one(write_spec):
    result = runner.invoke(app, ["endpoints", write_spec(minimal_spec(paths={"/a": {"get": op()}}))])

    assert "1 endpoint" in result.stdout
    assert "1 endpoints" not in result.stdout


# A spec with no paths gives an empty JSON list and exit 0.
def test_empty_spec_gives_empty_json(write_spec):
    result = runner.invoke(app, ["endpoints", write_spec(minimal_spec()), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == []


# Square brackets in the title or a path are shown as written, not read as rich styling.
def test_brackets_are_not_treated_as_markup(write_spec):
    spec = minimal_spec(info={"title": "[bold]Shop[/bold]", "version": "1"}, paths={"/a/[b]": {"get": op()}})

    result = runner.invoke(app, ["endpoints", write_spec(spec)])

    assert "[bold]Shop[/bold]" in result.stdout
    assert "/a/[b]" in result.stdout


# An error message containing brackets is printed as written too.
def test_error_with_brackets_is_printed_literally(tmp_path):
    missing = tmp_path / "[red]spec.json"

    result = runner.invoke(app, ["endpoints", str(missing)])

    assert result.exit_code == 2
    assert "[red]spec.json" in result.output


# Plain `apifuzz` shows the help text listing the endpoints command.
def test_no_arguments_shows_help():
    result = runner.invoke(app, [])

    assert "endpoints" in result.output
    assert "Usage" in result.output


# `python -m apifuzz` works the same as the installed command.
def test_python_dash_m_entry_point():
    result = subprocess.run([sys.executable, "-m", "apifuzz", "--version"], capture_output=True, text=True)

    assert result.returncode == 0
    assert result.stdout.strip() == f"apifuzz {__version__}"
