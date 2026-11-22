"""apifuzz practice API: a public test target for the hosted demo's "Your APIs".

FAKE DATA, SIMULATED FLAWS. This is not the VulnShop lab, which stays private because it runs a
real (in-memory) database. Here nothing is real: two made-up users, a few made-up orders, no
database, no files, no state kept between requests, and no requests to anywhere else. A planted
flaw only *behaves* like one, so apifuzz has something to find, and there is nothing behind it to
reach. That is what makes it safe to put on the internet.

One environment variable picks how it behaves:

  PRACTICE_VARIANT  "vulnerable" (default): the planted flaws below
                    "fixed": every flaw fixed; apifuzz should report nothing
  PRACTICE_SPEC     "published" (default): the spec is at /openapi.json
                    "hidden": /openapi.json answers 404, so the spec has to be uploaded
                    (the same file is in this folder as openapi.json)
  APIFUZZ_VERIFY    the line(s) the apifuzz web app gives you to prove you control this API,
                    served at /.well-known/apifuzz-verify.txt (separate several with spaces)

Planted flaws (vulnerable variant):
  GET  /orders/{id}   bola             login checked, ownership not
  GET  /users/{id}    auth-required    answers without a token
  POST /projects      mass-assignment  keeps fields the spec doesn't allow ("role", "owner"...)
  POST /login         rate-limit       no limit on attempts
  POST /login         injection        a quote in the username gives a database-style error
  GET  /search        rate-limit       no limit
  GET  /search?q=     injection        behaves like q pasted into a SQL string
Correct on purpose (nothing to report): GET /me, GET /orders, GET /products, GET /products/{id}
(shared with every user by design), GET /invoices/{id} (owner only).

Test accounts (public; they exist only here):
  alice / alice-practice   token practice-token-alice
  bob   / bob-practice     token practice-token-bob

Runs as a WSGI app on Vercel (api/index.py, every path rewritten to it by vercel.json), or
locally: python testapi/api/index.py [port]
"""

import base64
import binascii
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, unquote

BANNER = "apifuzz practice API: fake data and simulated flaws, for testing apifuzz only"
SPEC_FILE = Path(__file__).resolve().parent.parent / "openapi.json"
MAX_BODY = 16_384

USERS = {
    1: {"id": 1, "username": "alice", "password": "alice-practice", "email": "alice@practice.invalid"},
    2: {"id": 2, "username": "bob", "password": "bob-practice", "email": "bob@practice.invalid"},
}
TOKENS = {"practice-token-alice": 1, "practice-token-bob": 2}
ORDERS = {
    1001: {"id": 1001, "owner": 1, "item": "Notebook", "total": 12.5},
    1002: {"id": 1002, "owner": 1, "item": "Pens", "total": 4.2},
    2001: {"id": 2001, "owner": 2, "item": "Backpack", "total": 39.0},
}
INVOICES = {
    5001: {"id": 5001, "owner": 1, "amount": 16.7},
    6001: {"id": 6001, "owner": 2, "amount": 39.0},
}
PRODUCTS = {
    1: {"id": 1, "name": "Notebook", "price": 12.5},
    2: {"id": 2, "name": "Pens", "price": 4.2},
    3: {"id": 3, "name": "Backpack", "price": 39.0},
}
PROJECT_FIELDS = ("name", "description")  # what POST /projects is meant to accept

Response = tuple[int, Any, dict[str, str]]
StartResponse = Callable[[str, list[tuple[str, str]]], Any]


def variant() -> str:
    return "fixed" if os.environ.get("PRACTICE_VARIANT", "").strip().lower() == "fixed" else "vulnerable"


def fixed() -> bool:
    return variant() == "fixed"


def public(user: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in user.items() if k != "password"}


# ---- simulated SQL ------------------------------------------------------------------------------
# The vulnerable variant behaves as if the value were pasted into  ... WHERE name LIKE '%<q>%'
# without being parsed or run: an unbalanced quote is a "syntax error", and an always-true or
# always-false clause changes how many rows come back. There is no database behind it.

_COMMENT = re.compile(r"--.*$", re.S)


class SimulatedSqlError(Exception):
    pass


def _pasted(value: str) -> str:
    """What the clause after the value looks like once the value is pasted in and -- comments the rest."""
    return _COMMENT.sub("", value)


def simulated_like(value: str, rows: Iterable[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    clause = _pasted(value)
    if clause.count("'") % 2 == 1:
        raise SimulatedSqlError('unrecognized token: "\'"  (near the search value)')
    rows = list(rows)
    lowered = clause.replace(" ", "").lower()
    if "'or'1'='1" in lowered:
        return rows  # always true: every row
    if "'and'1'='2" in lowered:
        return []  # always false: nothing
    needle = value.split("'")[0].lower()
    return [r for r in rows if needle in str(r[field]).lower()]


# ---- a best-effort rate limit for the fixed variant ---------------------------------------------
# Serverless instances share no memory, so the count is per instance. The RateLimit headers are
# sent on every answer either way, which is how a client (and apifuzz) learns the limit exists.

_hits: dict[str, list[float]] = {}
_hits_lock = threading.Lock()
LIMIT, WINDOW = 10, 60.0


def limited(key: str) -> tuple[bool, dict[str, str]]:
    now = time.monotonic()
    with _hits_lock:
        if len(_hits) > 1000:
            _hits.clear()
        recent = [t for t in _hits.get(key, []) if t > now - WINDOW] + [now]
        _hits[key] = recent
    left = max(0, LIMIT - len(recent))
    headers = {"RateLimit-Limit": str(LIMIT), "RateLimit-Remaining": str(left), "RateLimit-Reset": str(int(WINDOW))}
    if len(recent) > LIMIT:
        headers["Retry-After"] = str(int(WINDOW))
        return True, headers
    return False, headers


# ---- projects: kept in the id itself, so nothing is stored ---------------------------------------
# A created project is returned with an id that encodes the project. GET /projects/{id} decodes
# it, DELETE has nothing to remove. That is enough for a create, read back and clean up. Ids stay
# short (scanners, apifuzz among them, take ids of up to 64 characters): known fields get one-letter
# keys and fields at their default value are left out. Other fields are not kept.

SHORT = {"name": "n", "description": "d", "role": "r", "owner": "o", "is_admin": "a", "verified": "v"}
LONG = {v: k for k, v in SHORT.items()}
DEFAULTS: dict[str, Any] = {"description": "", "role": "member"}
MAX_ID = 64


def encode_id(project: dict[str, Any]) -> str | None:
    """The project as a short id, or None if it doesn't fit in one."""
    compact = {SHORT[k]: v for k, v in project.items() if k in SHORT and DEFAULTS.get(k, object()) != v}
    raw = json.dumps(compact, separators=(",", ":"), sort_keys=True).encode()
    text = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return text if len(text) <= MAX_ID else None


def decode_id(project_id: str) -> dict[str, Any] | None:
    if len(project_id) > MAX_ID:
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(project_id + "=" * (-len(project_id) % 4)))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(data, dict) or any(k not in LONG for k in data):
        return None
    if not all(v is None or isinstance(v, (bool, int, float, str)) for v in data.values()):
        return None
    project = {**DEFAULTS, **{LONG[k]: v for k, v in data.items()}}
    return project if isinstance(project.get("name"), str) else None


# ---- the routes ---------------------------------------------------------------------------------

def caller(headers: dict[str, str]) -> int | None:
    auth = headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return TOKENS.get(auth[7:].strip())


def number_after(prefix: str, path: str) -> int | None:
    rest = path[len(prefix):]
    return int(rest) if rest.isdigit() and len(rest) < 10 else None


def spec(host: str) -> dict[str, Any]:
    document = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    document["servers"] = [{"url": f"https://{host}"}] if host else document.get("servers", [])
    return document


def verify_file() -> str | None:
    lines = [v for v in os.environ.get("APIFUZZ_VERIFY", "").split() if v]
    if not lines:
        return None
    return "\n".join(line if line.startswith("apifuzz-verify=") else f"apifuzz-verify={line}" for line in lines) + "\n"


def handle(method: str, path: str, query: dict[str, list[str]], headers: dict[str, str], body: bytes) -> Response:
    uid = caller(headers)
    login_required: Response = (401, {"error": "login required"}, {"WWW-Authenticate": "Bearer"})

    if method == "GET":
        if path in ("/", "/health"):
            return 200, {"status": "ok", "api": BANNER, "variant": variant()}, {}
        if path == "/openapi.json":
            if os.environ.get("PRACTICE_SPEC", "").strip().lower() == "hidden":
                return 404, {"error": "this API doesn't publish its spec: upload openapi.json instead"}, {}
            return 200, spec(headers.get("host", "")), {}
        if path == "/.well-known/apifuzz-verify.txt":
            text = verify_file()
            return (200, text, {}) if text else (404, {"error": "no proof set (APIFUZZ_VERIFY)"}, {})
        if path == "/me":
            return (200, public(USERS[uid]), {}) if uid else login_required
        if path == "/orders":
            return (200, [o for o in ORDERS.values() if o["owner"] == uid], {}) if uid else login_required
        if path.startswith("/orders/"):
            if not uid:
                return login_required
            order = ORDERS.get(number_after("/orders/", path) or 0)
            # PLANTED (bola): logged in is checked; whose order it is, is not.
            if order is None or (fixed() and order["owner"] != uid):
                return 404, {"error": "no such order"}, {}
            return 200, order, {}
        if path.startswith("/users/"):
            # PLANTED (auth-required): the spec says a token is needed; this doesn't ask for one.
            if fixed() and not uid:
                return login_required
            user = USERS.get(number_after("/users/", path) or 0)
            if user is None or (fixed() and user["id"] != uid):
                return 404, {"error": "no such user"}, {}
            return 200, public(user), {}
        if path == "/products":
            return (200, list(PRODUCTS.values()), {}) if uid else login_required
        if path.startswith("/products/"):
            if not uid:
                return login_required
            product = PRODUCTS.get(number_after("/products/", path) or 0)
            return (200, product, {}) if product else (404, {"error": "no such product"}, {})
        if path.startswith("/invoices/"):
            if not uid:
                return login_required
            invoice = INVOICES.get(number_after("/invoices/", path) or 0)
            if invoice is None or invoice["owner"] != uid:
                return 404, {"error": "no such invoice"}, {}
            return 200, invoice, {}
        if path == "/search":
            if not uid:
                return login_required
            extra: dict[str, str] = {}
            if fixed():
                blocked, extra = limited(f"search:{uid}")
                if blocked:
                    return 429, {"error": "too many searches"}, extra
            q = (query.get("q") or [""])[0][:200]
            if fixed():
                return 200, [p for p in PRODUCTS.values() if q.lower() in p["name"].lower()], extra
            try:
                return 200, simulated_like(q, PRODUCTS.values(), "name"), extra  # PLANTED (injection)
            except SimulatedSqlError as exc:
                return 500, {"error": f"SQL error: {exc}"}, extra
        if path.startswith("/projects/"):
            if not uid:
                return login_required
            project = decode_id(path[len("/projects/"):])
            if project is None or project.get("owner") != uid:
                return 404, {"error": "no such project"}, {}
            return 200, project, {}

    if method == "POST":
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            return 400, {"error": "the body must be JSON"}, {}
        if not isinstance(data, dict):
            return 400, {"error": "the body must be a JSON object"}, {}
        if path == "/login":
            extra = {}
            if fixed():
                blocked, extra = limited("login")
                if blocked:
                    return 429, {"error": "too many attempts"}, extra
            username, password = data.get("username"), data.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                return 400, {"error": "username and password are required"}, extra
            # PLANTED (injection): behaves as if the username were pasted into
            # WHERE username = '<username>'. The password is still checked separately.
            if not fixed() and _pasted(username).count("'") % 2 == 1:
                return 500, {"error": 'SQL error: unrecognized token: "\'"  (near the username)'}, extra
            user = next((u for u in USERS.values() if u["username"] == username), None)
            if user is None or user["password"] != password:
                return 401, {"error": "wrong username or password"}, extra
            token = next(t for t, i in TOKENS.items() if i == user["id"])
            return 200, {"token": token}, extra
        if path == "/projects":
            if not uid:
                return login_required
            name = data.get("name")
            if not isinstance(name, str) or not 1 <= len(name) <= 100:
                return 400, {"error": "name is required (1 to 100 characters)"}, {}
            # PLANTED (mass-assignment): every field in the body is kept, "role" included.
            source = {k: data[k] for k in PROJECT_FIELDS if k in data} if fixed() else data
            project = {"description": "", "role": "member", **source, "owner": uid}
            if not fixed() and "owner" in data:
                project["owner"] = data["owner"]  # even the owner can be set by the caller
            project = {k: v for k, v in project.items() if k in SHORT}
            project_id = encode_id(project)
            if project_id is None:
                return 400, {"error": "too long for this practice API: keep names and values short"}, {}
            return 201, {"id": project_id, **project}, {}

    if method == "DELETE" and path.startswith("/projects/"):
        if not uid:
            return login_required
        project = decode_id(path[len("/projects/"):])
        if project is None or project.get("owner") != uid:
            return 404, {"error": "no such project"}, {}
        return 204, None, {}  # nothing is stored, so there is nothing to remove

    known = re.match(r"^/(health|openapi\.json|me|orders|users|products|invoices|search|login|projects)(/|$)", path)
    return (405, {"error": "method not allowed"}, {}) if known else (404, {"error": "not found"}, {})


def app(environ: dict[str, Any], start_response: StartResponse) -> list[bytes]:
    """The WSGI entry point Vercel calls (and the local server below)."""
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = unquote(environ.get("PATH_INFO", "/")) or "/"
    query = parse_qs(environ.get("QUERY_STRING", ""))
    headers = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_")}
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length > MAX_BODY:
        status, payload, extra = 413, {"error": "the body is too large"}, {}
    else:
        body = environ["wsgi.input"].read(length) if length else b""
        status, payload, extra = handle(method, path, query, headers, body)

    if payload is None:
        data, kind = b"", "application/json"
    elif isinstance(payload, str):
        data, kind = payload.encode(), "text/plain; charset=utf-8"
    else:
        data, kind = json.dumps(payload).encode(), "application/json"
    reasons = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
               404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large", 429: "Too Many Requests",
               500: "Internal Server Error"}
    response_headers = [
        ("Content-Type", kind),
        ("Content-Length", str(len(data))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Robots-Tag", "noindex"),
        ("X-Practice-API", BANNER),
        *extra.items(),
    ]
    start_response(f"{status} {reasons.get(status, 'Status')}", response_headers)
    return [data]


if __name__ == "__main__":
    import sys
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    class Quiet(WSGIRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8020
    print(f"{BANNER} ({variant()}) on http://127.0.0.1:{port}")
    make_server("127.0.0.1", port, app, handler_class=Quiet).serve_forever()
