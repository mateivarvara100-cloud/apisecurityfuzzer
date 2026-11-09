"""Command-line interface: `apifuzz endpoints`, `apifuzz checks` and `apifuzz scan`."""

import json  # used for the --json output
from enum import Enum  # a fixed set of allowed values for an option (see AuthFilter)
from fnmatch import fnmatchcase  # shell-style patterns like "/orders/*" for --path
from pathlib import Path  # the --html output file
from typing import Annotated, NoReturn  # lets us attach CLI settings to a parameter's type hint

import typer  # builds the command-line interface from ordinary Python functions
from rich.console import Console  # prints styled, colored output to the terminal
from rich.table import Table  # draws the endpoints table
from rich.text import Text  # plain text that rich will NOT try to interpret as markup

from apifuzz import __version__
from apifuzz.checks import ScanContext, all_checks, select_checks
from apifuzz.endpoint_model import HTTP_METHODS, Endpoint, build_endpoints
from apifuzz.errors import AllowlistError, ApifuzzError, RequestError, SessionError
from apifuzz.finding import Severity
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.report import findings_table, to_html, to_json
from apifuzz.scanner import run_scan
from apifuzz.docker_verify import verify_targets
from apifuzz.session_manager import authenticate
from apifuzz.settings import host_entry, resolve_settings
from apifuzz.spec_loader import load_spec

# The `apifuzz` command itself. pyproject.toml points the installed command at this object.
app = typer.Typer(
    help="Find OWASP API Top 10 flaws in an API you are authorized to test.",
    no_args_is_help=True,  # plain `apifuzz` with nothing after it shows the help text
    add_completion=False,  # hide typer's shell-completion install options (not needed)
)

_out = Console()  # normal output goes to stdout
_err = Console(stderr=True)  # errors go to stderr, so `apifuzz ... > file` doesn't capture them


def _show_version(value: bool) -> None:
    # Called by typer as soon as it sees --version (see is_eager below).
    if value:
        typer.echo(f"apifuzz {__version__}")
        raise typer.Exit()  # stop here with exit code 0; don't go on to run a subcommand


# @app.callback() runs before any subcommand. Its options belong to `apifuzz` itself,
# e.g. `apifuzz --version`, rather than to a subcommand like `apifuzz endpoints`.
@app.callback()
def main(
    version: Annotated[
        bool,
        # is_eager=True makes typer handle this option before everything else, so
        # `apifuzz --version` works even though no subcommand was given.
        typer.Option("--version", callback=_show_version, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    pass  # nothing to do here; the work happens in the callback and the subcommands


class AuthFilter(str, Enum):
    # The values --auth accepts. typer shows them in --help and rejects anything else.
    login = "login"  # only endpoints that need a login
    none = "none"  # only endpoints anyone can call


def _check_methods(methods: list[str] | None) -> set[str]:
    # Upper-case the --method values and reject unknown ones before any work is done.
    wanted = {m.upper() for m in methods or []}
    unknown = sorted(wanted - {m.upper() for m in HTTP_METHODS})
    if unknown:
        # BadParameter makes typer print a usage error and exit with code 2.
        raise typer.BadParameter(f"unknown HTTP method: {', '.join(unknown)}", param_hint="--method")
    return wanted


def _filter_endpoints(
    everything: list[Endpoint],
    methods: set[str],
    path_pattern: str | None,
    tags: list[str] | None,
    auth: "AuthFilter | None",
) -> list[Endpoint]:
    # Keep the endpoints that match every filter given. Shared by `endpoints` and `scan`.
    return [
        e
        for e in everything
        if (not methods or e.method in methods)
        # fnmatchcase: "*" matches anything, and upper/lower case must match (paths are case-sensitive).
        and (path_pattern is None or fnmatchcase(e.path, path_pattern))
        and (not tags or any(t in e.tags for t in tags))
        and (auth is None or e.requires_auth == (auth is AuthFilter.login))
    ]


def _load_or_exit(spec: str) -> dict:
    try:
        return load_spec(spec)
    except ApifuzzError as exc:
        _fail(exc)


def _fail(exc: Exception) -> NoReturn:
    # An expected problem (bad spec, missing file, bad config): print one clean red line, no
    # traceback. markup=False and highlight=False stop rich from treating "[...]" in the message
    # as styling tags or coloring parts of it. Exit code 2 tells scripts and CI it failed.
    _err.print(f"error: {exc}", style="red", markup=False, highlight=False)
    raise typer.Exit(code=2) from exc


# @app.command() turns the function into a subcommand named after it: `apifuzz endpoints`.
# Each function parameter becomes a CLI argument or option.
@app.command()
def endpoints(
    # typer.Argument = positional: `apifuzz endpoints openapi.json`
    spec: Annotated[str, typer.Argument(help="Path or http(s) URL of an OpenAPI/Swagger spec.")],
    # typer.Option = a named flag. A bool option is off unless the flag is given.
    as_json: Annotated[bool, typer.Option("--json", help="Print the endpoints as JSON instead of a table.")] = False,
    # A list option can be given several times: `-m GET -m POST`.
    methods: Annotated[
        list[str] | None,
        typer.Option("--method", "-m", help="Only show this HTTP method. Repeat for several (-m GET -m POST)."),
    ] = None,
    path_pattern: Annotated[
        str | None,
        typer.Option("--path", "-p", help="Only show paths matching this pattern, e.g. '/orders*' or '*{id}'."),
    ] = None,
    tags: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t", help="Only show endpoints with this tag. Repeat for several."),
    ] = None,
    auth: Annotated[
        AuthFilter | None,
        typer.Option("--auth", help="Only show endpoints that need a login (login) or don't (none)."),
    ] = None,
    i_have_authorization: Annotated[
        bool,
        typer.Option(
            "--i-have-authorization",
            help="Confirm you are allowed to test the target. Not needed to list endpoints; "
            "scanning commands will require it.",
        ),
    ] = False,  # accepted but unused until the scanning commands exist (Phase 1)
) -> None:
    """List every endpoint found in a spec. Sends no requests to the API itself."""
    wanted_methods = _check_methods(methods)  # fail fast on a typo, before reading the spec
    document = _load_or_exit(spec)
    everything = build_endpoints(document)
    found = _filter_endpoints(everything, wanted_methods, path_pattern, tags, auth)
    if as_json:
        # model_dump() turns each pydantic Endpoint into a plain dict that json can serialize.
        typer.echo(json.dumps([e.model_dump() for e in found], indent=2))
        return
    _out.print(_endpoint_table(found, document.get("info") or {}, total=len(everything)))


def _endpoint_table(found: list[Endpoint], info: dict, *, total: int) -> Table:
    # Title like "VulnShop (sample) 1.0.0", taken from the spec's "info" section.
    # Text(...) so a title such as "[bold]Shop" is shown as written, not as rich styling.
    title = info.get("title") or "API"
    count = f"{len(found)} endpoint{'' if len(found) == 1 else 's'}"
    if len(found) != total:  # a filter hid some: say how many there are in all
        count = f"{len(found)} of {total} endpoints"
    table = Table(title=Text(f"{title} {info.get('version', '')}".strip()), caption=count)
    table.add_column("Method", no_wrap=True)  # no_wrap: never split "PATCH" across two lines
    table.add_column("Path")
    table.add_column("Parameters")
    table.add_column("Body fields")
    table.add_column("Auth", no_wrap=True)
    for endpoint in found:
        table.add_row(
            endpoint.method,
            # Text(...) shows the value literally. A path could contain "[", which rich would
            # otherwise read as a style tag.
            Text(endpoint.path),
            # e.g. "id (path), q (query)", or "-" when there are none.
            Text(", ".join(f"{p.name} ({p.location})" for p in endpoint.parameters) or "-"),
            # e.g. "username*, password*": a * marks a required field.
            Text(", ".join(f"{f.name}*" if f.required else f.name for f in endpoint.request_fields) or "-"),
            "login" if endpoint.requires_auth else "none",
            # Deprecated operations get dimmed: often forgotten, so worth a look in later phases.
            style="dim" if endpoint.deprecated else None,
        )
    return table


class FailOn(str, Enum):
    # The lowest severity that makes `scan` exit with code 1 (useful in CI). "never" always exits 0.
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    never = "never"


@app.command("checks")
def list_checks() -> None:
    """List the security checks `scan` can run."""
    table = Table(title="Available checks")
    table.add_column("Id", no_wrap=True)
    table.add_column("Default", no_wrap=True)
    table.add_column("What it looks for")
    for cls in all_checks():
        table.add_row(cls.id, "yes" if cls.default else "no", Text(cls.description))
    _out.print(table)


@app.command()
def scan(
    spec: Annotated[str, typer.Argument(help="Path or http(s) URL of an OpenAPI/Swagger spec.")],
    i_have_authorization: Annotated[
        bool,
        typer.Option(
            "--i-have-authorization",
            help="Required. Confirms you own the target or have written permission to test it.",
        ),
    ] = False,
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Root URL of the API. Default: APIFUZZ_BASE_URL, then the spec's servers."),
    ] = None,
    allow: Annotated[
        list[str] | None,
        typer.Option(
            "--allow",
            help="Extra host or host:port the scan may contact. Repeatable. The base URL's host is always allowed.",
        ),
    ] = None,
    only: Annotated[
        list[str] | None, typer.Option("--only", help="Run only this check id. Repeatable. See `apifuzz checks`.")
    ] = None,
    skip: Annotated[list[str] | None, typer.Option("--skip", help="Don't run this check id. Repeatable.")] = None,
    methods: Annotated[
        list[str] | None, typer.Option("--method", "-m", help="Only scan this HTTP method. Repeatable.")
    ] = None,
    path_pattern: Annotated[
        str | None, typer.Option("--path", "-p", help="Only scan paths matching this pattern, e.g. '/orders*'.")
    ] = None,
    tags: Annotated[list[str] | None, typer.Option("--tag", "-t", help="Only scan endpoints with this tag.")] = None,
    auth: Annotated[
        AuthFilter | None, typer.Option("--auth", help="Only scan endpoints that need a login (login) or don't (none).")
    ] = None,
    require_docker: Annotated[
        bool | None,
        typer.Option(
            "--require-docker/--no-require-docker",
            help="Only scan if every target is a running local Docker container. "
            "Default: APIFUZZ_REQUIRE_DOCKER, else off.",
        ),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=0.1, help="Seconds to wait for each response.")] = 10.0,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="Exit with code 1 if any finding is at least this severe.")
    ] = FailOn.high,
    as_json: Annotated[bool, typer.Option("--json", help="Print the results as JSON (secrets redacted).")] = False,
    html_path: Annotated[
        Path | None, typer.Option("--html", help="Also write a standalone HTML report to this file.", dir_okay=False)
    ] = None,
    redact: Annotated[
        bool,
        typer.Option(
            "--redact/--no-redact",
            help="Hide Authorization, cookie and API-key values in JSON/HTML reports. On by default.",
        ),
    ] = True,
) -> None:
    """Run security checks against an API you are authorized to test.

    Test accounts are read only from the environment or .env, never from flags, so they don't end
    up in shell history: APIFUZZ_TOKEN_A / _B, or APIFUZZ_USER_A / APIFUZZ_PASSWORD_A (and B) to
    log in through APIFUZZ_LOGIN_PATH (default /login).
    """
    if not i_have_authorization:
        _err.print(
            "error: scanning sends requests to the target. Re-run with --i-have-authorization to "
            "confirm you own it or have written permission to test it.",
            style="red",
            markup=False,
            highlight=False,
        )
        raise typer.Exit(code=2)

    wanted_methods = _check_methods(methods)
    try:
        chosen = select_checks(only, skip)
    except KeyError as exc:
        raise typer.BadParameter(str(exc.args[0]), param_hint="--only/--skip") from exc

    document = _load_or_exit(spec)
    try:
        settings = resolve_settings(spec=document, base_url=base_url, allowlist=allow, require_docker=require_docker)
        if settings.require_docker:
            # Confirm the base URL and every extra entry belong to running containers, then allow
            # ONLY those exact host:port pairs (a bare "localhost" would allow every local port).
            base = host_entry(settings.base_url)
            extras = [e for e in settings.allowlist if e != base]
            matches = verify_targets(settings.base_url, extras)
            for m in matches:
                _err.print(
                    f"verified: {m.entry} is container {m.container.name} ({m.container.image}), which {m.how}",
                    style="green", markup=False, highlight=False,
                )
            allowlist = Allowlist([m.entry for m in matches])
        else:
            allowlist = Allowlist(settings.allowlist)
    except (ApifuzzError, ValueError) as exc:  # ValueError: a malformed allowlist entry
        _fail(exc)

    targets = _filter_endpoints(build_endpoints(document), wanted_methods, path_pattern, tags, auth)
    try:
        with HttpClient(allowlist, timeout=timeout) as client:
            # Log in the test accounts that have a username/password but no token.
            settings = authenticate(client, settings)
            if any(c.id == "bola" for c in chosen) and not (settings.token_a and settings.token_b):
                _err.print(
                    "note: the bola check was skipped because it needs two accounts. Set APIFUZZ_TOKEN_A "
                    "and APIFUZZ_TOKEN_B, or APIFUZZ_USER_A/APIFUZZ_PASSWORD_A and the same for B.",
                    style="yellow", markup=False, highlight=False,
                )
            _err.print(
                f"Scanning {len(targets)} endpoint(s) at {settings.base_url} with {len(chosen)} check(s)...",
                markup=False,
                highlight=False,
            )
            result = run_scan(targets, chosen, ScanContext(client, settings))
    except (AllowlistError, SessionError, RequestError) as exc:
        # A refused host is a misconfiguration; a failed login means the checks can't be trusted.
        _fail(exc)

    if html_path is not None:
        title = f"apifuzz report: {document.get('info', {}).get('title', 'API')}"
        try:
            html_path.write_text(to_html(result, title=title, redact=redact), encoding="utf-8")
        except OSError as exc:
            _fail(ApifuzzError(f"could not write the HTML report to {html_path}: {exc}"))
        _err.print(f"HTML report written to {html_path}", markup=False, highlight=False)

    if as_json:
        typer.echo(to_json(result, redact=redact))
    else:
        _out.print(findings_table(result))
        for line in result.errors:
            _err.print(f"warning: {line}", style="yellow", markup=False, highlight=False)

    threshold = None if fail_on is FailOn.never else Severity[fail_on.value.upper()]
    if threshold is not None and any(f.severity >= threshold for f in result.findings):
        raise typer.Exit(code=1)


@app.command("verify-docker")
def verify_docker(
    target: Annotated[str, typer.Argument(help="A URL or host:port, e.g. http://localhost:8000")],
) -> None:
    """Check that a target is served by a running local Docker container. Sends no requests to it."""
    try:
        (match,) = verify_targets(target, [])
    except ApifuzzError as exc:
        _fail(exc)
    c = match.container
    _out.print(f"ok: {match.entry} is container {c.name} ({c.image}, id {c.id}), which {match.how}",
               markup=False, highlight=False)
