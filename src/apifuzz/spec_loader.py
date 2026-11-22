"""Load an OpenAPI/Swagger spec from a file or URL, resolve its $refs and validate it.

The one public function is load_spec(); everything else in this file is a helper for it.
Its output (a plain Python dict) is the input to endpoint_model.build_endpoints().
"""

import json  # to tell a JSON spec (which can't contain YAML aliases) from a YAML one
import re  # regular expressions: used to cut prance's fake filename out of error messages
from pathlib import Path  # file paths as objects; Path(...).read_text() reads a whole file
from typing import Any  # type hint meaning "any value" (a spec can contain anything)

import httpx  # HTTP library; used here only to download a spec when given a URL
from prance import ResolvingParser, ValidationError  # prance parses, fills in $refs, validates
from prance.util.formats import parse_spec  # prance's JSON/YAML reader, used before resolving
from prance.util.resolver import RESOLVE_INTERNAL  # follow only "#/..." references
from prance.util.url import ResolutionError  # what prance raises when a $ref points nowhere

from apifuzz import __version__
from apifuzz.errors import SpecError  # our error type for "something is wrong with the spec"
from apifuzz.http_client import Allowlist

# How many seconds to wait for a spec download before giving up.
_FETCH_TIMEOUT = 15.0

# prance parses from a string using a made-up file name; keep that out of error messages.
# Matches e.g. "file:///c:/__placeholder_url__.yaml" and stops before "#", so the useful part
# that follows (like "#/components/schemas/Nope") stays in the message.
_PLACEHOLDER_URL = re.compile(r"file:///[^#\s\"']*__placeholder_url__\.yaml")


def load_spec(
    source: str,
    *,
    client: httpx.Client | None = None,
    follow_redirects: bool = True,
    allowlist: Allowlist | None = None,
    allow_yaml_aliases: bool = True,
) -> dict[str, Any]:
    """Return the validated spec at `source` (a file path or http(s) URL) with internal $refs inlined.

    Raises SpecError with a readable message for anything wrong with the spec.
    `client` is only used for URL sources and exists so tests can inject a mock transport.

    Downloading a spec is a request like any other, so it can be held to the same rules as scan
    traffic. `allowlist`, when given, must permit the URL or AllowlistError is raised before
    anything is sent. `follow_redirects=False` makes a redirected spec URL an error, so the
    download can't be sent on to a host nobody approved. `scan` uses both; `endpoints`, which
    sends nothing but this one download, uses neither.

    `allow_yaml_aliases=False` refuses a YAML spec that uses anchors and aliases (&name, *name);
    see load_spec_text().
    """
    # Step 1: get the raw text, from disk or from the network.
    text = _read_source(source, client, follow_redirects, allowlist)
    return load_spec_text(text, source, allow_yaml_aliases=allow_yaml_aliases)


def load_spec_text(text: str, source: str = "the spec", *, allow_yaml_aliases: bool = True) -> dict[str, Any]:
    """Return the validated spec in `text` (JSON or YAML) with internal $refs inlined.

    The same as load_spec() for a spec that is already in hand, such as an uploaded file: nothing
    is read or downloaded, and a $ref that points outside the spec is refused. `source` names the
    spec in error messages.

    `allow_yaml_aliases=False` is for specs from people you don't trust, such as on a server. A
    YAML alias repeats an earlier part of the document, and aliases of aliases grow it
    exponentially: a few hundred bytes can expand to billions of nodes and keep the parser busy
    for hours (the "billion laughs" attack). JSON has no aliases, so JSON specs are unaffected.
    """
    # Step 2: an empty file would make prance crash with a confusing internal error, so catch it here.
    if not text.strip():
        raise SpecError(f"{source}: the spec is empty")
    # Step 2b: a $ref may only point inside this spec ("#/components/..."). One that names another
    # document ("http://...", "other.yaml#/...", "file:///...") would make prance fetch that URL or
    # read that file, which a spec must never be able to do: a downloaded spec could otherwise
    # point the scanner at internal addresses or local files, past the allowlist.
    if not allow_yaml_aliases:
        _refuse_yaml_aliases(source, text)
    _refuse_external_refs(source, text)

    # Step 3: let prance parse the text, replace every $ref with its real content, and validate.
    try:
        parser = ResolvingParser(
            spec_string=text,  # we pass the text itself, so files and URLs share one code path
            backend="openapi-spec-validator",  # which library checks the spec against OpenAPI rules
            strict=True,  # an invalid spec raises an error instead of only printing a warning
            # prance itself resolves only "#/..." references. This is not what keeps other documents
            # out (the validator can still fetch one): _refuse_external_refs above is.
            resolve_types=RESOLVE_INTERNAL,
            recursion_limit_handler=_cut_recursive_ref,  # what to do with self-referencing schemas
        )
    except ValidationError as exc:
        # The spec breaks the OpenAPI rules (or isn't JSON/YAML at all).
        # `from exc` keeps the original error attached for debugging; the user sees our message.
        raise SpecError(f"{source}: {_describe_validation_error(exc)}") from exc
    except ResolutionError as exc:
        # A $ref points at something that doesn't exist, e.g. "#/components/schemas/Nope".
        raise SpecError(f"{source}: could not resolve a reference: {_clean(str(exc))}") from exc

    # The finished result: a plain dict with no $refs left in it.
    return parser.specification


def _read_source(
    source: str, client: httpx.Client | None, follow_redirects: bool = True, allowlist: Allowlist | None = None
) -> str:
    # Anything starting with http:// or https:// is downloaded; everything else is a file path.
    if source.lower().startswith(("http://", "https://")):
        if allowlist is not None:
            allowlist.check(source)  # raises AllowlistError before anything is sent
        return _fetch(source, client, follow_redirects)
    # "ftp://...", "file://..." etc. would otherwise be treated as an odd file name.
    # (A Windows path like C:\spec.json has no "://", so it isn't caught here.)
    if "://" in source:
        scheme = source.split("://", 1)[0]
        raise SpecError(f"{source}: unsupported URL scheme '{scheme}'; use a file path or an http(s) URL")
    path = Path(source)
    if path.is_dir():
        # Windows reports reading a folder as "Permission denied", which sends people the wrong way.
        raise SpecError(f"{source}: is a folder, not a spec file")
    try:
        return path.read_text(encoding="utf-8")  # specs are UTF-8 text
    except FileNotFoundError:
        # `from None` hides Python's own FileNotFoundError: our message already says everything.
        raise SpecError(f"{source}: file not found") from None
    except (OSError, UnicodeDecodeError) as exc:
        # Any other read problem: no permission, it's a folder, it isn't text...
        raise SpecError(f"{source}: could not read file: {exc}") from exc


def _fetch(url: str, client: httpx.Client | None, follow_redirects: bool = True) -> str:
    # Fetching the spec is a plain GET of a document; scan traffic goes through HttpClient instead.
    # Remember whether WE create the client: we must only close a client we created ourselves,
    # never one a test passed in.
    owns_client = client is None
    # Following redirects is allowed only when the caller says so (the scanner's HttpClient never
    # does). The User-Agent names the tool, as scan requests do.
    client = client or httpx.Client(
        timeout=_FETCH_TIMEOUT, follow_redirects=follow_redirects, headers={"User-Agent": f"apifuzz/{__version__}"}
    )
    try:
        response = client.get(url)
        if response.is_redirect:
            # Only reached when redirects are not followed: say where it points instead of "HTTP 302".
            raise SpecError(
                f"{url}: the spec URL redirects to {response.headers.get('location', 'another address')} "
                f"(HTTP {response.status_code}). Redirects are not followed here; use the final URL."
            )
        response.raise_for_status()  # turns a 4xx/5xx answer into an HTTPStatusError exception
        return response.text
    except httpx.HTTPStatusError as exc:
        # The server answered, but with an error code like 404 or 500.
        raise SpecError(f"{url}: server answered HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        # The server didn't answer at all: connection refused, DNS failure, timeout...
        raise SpecError(f"{url}: could not fetch spec: {exc}") from exc
    finally:
        # `finally` runs whether we returned or raised, so the connection is always cleaned up.
        if owns_client:
            client.close()


def _refuse_yaml_aliases(source: str, text: str) -> None:
    """Raise SpecError if YAML `text` uses an alias. Reads the event stream, so nothing is expanded."""
    try:
        json.loads(text)
        return  # JSON: no aliases possible
    except ValueError:
        pass
    from ruamel.yaml import YAML  # prance's own YAML library
    from ruamel.yaml.events import AliasEvent

    try:
        for event in YAML(typ="safe").parse(text):
            if isinstance(event, AliasEvent):
                raise SpecError(
                    f"{source}: the spec uses YAML aliases (*name), which aren't accepted here because "
                    "they can make a small file expand without limit. Write the repeated parts out, or "
                    "use $ref, or upload it as JSON."
                )
    except SpecError:
        raise
    except Exception:  # noqa: BLE001 - not valid YAML: prance reports that itself, with a better message
        return


def _refuse_external_refs(source: str, text: str) -> None:
    """Raise SpecError if any $ref points outside the spec. Text that doesn't parse is left to prance."""
    try:
        document = parse_spec(text)
    except Exception:  # noqa: BLE001 - prance reports a broken document itself, with a better message
        return
    stack: list[Any] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                shown = ref if len(ref) <= 120 else ref[:117] + "..."
                raise SpecError(
                    f"{source}: a $ref points outside the spec ({shown}). apifuzz follows only references "
                    "inside the spec (#/...); bundle the spec into one document first."
                )
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def _cut_recursive_ref(limit: int, parsed_url: Any, recursions: Any = ()) -> dict[str, Any]:
    # Self-referencing schemas (a tree of categories, say) are legal and common. prance's default
    # is to give up; instead we stop expanding at the point of recursion.
    # prance calls this function when it hits the loop, and puts whatever we return in place of
    # the $ref. An empty dict means "stop here". The arguments are required by prance but unused.
    return {}


def _describe_validation_error(exc: ValidationError) -> str:
    # prance stores the readable message as the first argument of the exception.
    message = str(exc.args[0]) if exc.args else "the document is not a valid OpenAPI spec"
    # The validator's message can run to dozens of lines; the first line is the useful summary.
    message = message.splitlines()[0] if message else message
    # __cause__ is the lower-level error prance wrapped (from openapi-spec-validator, when
    # validation failed). It knows WHERE in the spec the problem is.
    cause = exc.__cause__
    # No underlying cause + "Could not parse" means the text wasn't JSON/YAML in the first place.
    if cause is None and message.startswith("Could not parse"):
        return "not valid JSON or YAML, or not an OpenAPI document"
    # `path` is the list of keys leading to the problem, e.g. ["info"] or ["paths", "/a", "get"].
    # getattr(..., ()) returns an empty tuple if the cause has no `path` (or there is no cause).
    location = "/".join(str(part) for part in getattr(cause, "path", ()))
    if location:
        return f"invalid spec at '{location}': {message}"
    return f"invalid spec: {message}"


def _clean(message: str) -> str:
    # Replace prance's fake filename with nothing (see _PLACEHOLDER_URL at the top of the file).
    return _PLACEHOLDER_URL.sub("", message).strip()
