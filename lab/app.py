"""VulnShop lab: a tiny API matching tests/data/sample_openapi.json, for testing apifuzz locally.

LAB USE ONLY. It has deliberately planted flaws so each apifuzz check has something to find.
Each planted flaw is marked "PLANTED" with the check that should report it. Everything else
behaves correctly, so a check that flags it has a false positive.

Uses only the Python standard library. The data is seeded the same way on every start, lives in
memory, and resets when the container restarts. It refuses to start unless DEMO_MODE=1, and every
response carries an X-VulnShop-Lab header, so it can't be mistaken for (or deployed as) a real service.

Ground truth (what apifuzz should and should not report):
  GET /orders/{id}    bola           login checked, ownership not (Alice can read Bob's order)
  GET /users/{id}     auth-required  no login check at all
  PATCH /users/{id}   mass-assignment  saves every field in the body, including "role"
  POST /login         rate-limit     any number of login attempts is accepted
  POST /login         injection      username is pasted into a SQL user lookup (password still checked)
  GET /search         rate-limit     any number of searches is accepted
  GET /search?q=      injection      q is pasted into a SQL query string (also rate-limit, above)
  GET /catalog/{name} injection      the path value is pasted into a SQL query string
  GET /stock          injection      the X-Warehouse header is pasted into a SQL query string
  GET /me             nothing        correctly protected (false-positive guard)
  GET /orders         nothing        lists only the caller's own orders
  POST /orders        nothing        saves only the fields the spec allows (DELETE cleans up)
  GET /products/{id}  nothing        shared on purpose: every logged-in user may read every product
  GET /invoices/{id}  nothing        correctly protected: only the owner can read an invoice

With LAB_HARDENED=1 every planted flaw is fixed, and apifuzz must report nothing at all
(the known-negative variant).
"""

import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SPEC_PATH = Path(os.environ.get("SPEC_PATH", "/app/openapi.json"))
def hardened() -> bool:
    """LAB_HARDENED=1 turns off every planted flaw. Read per request so tests can switch it."""
    return os.environ.get("LAB_HARDENED") == "1"


BANNER = "VulnShop LAB: deliberately vulnerable, for local apifuzz testing only. Never deploy it."

# Two lab accounts. Their tokens are fixed so .env can hold them: APIFUZZ_TOKEN_A / _B.
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@lab.test", "role": "user", "password": "alice"},
    2: {"id": 2, "name": "Bob", "email": "bob@lab.test", "role": "user", "password": "bob"},
}
TOKENS = {"lab-token-alice": 1, "lab-token-bob": 2}
ORDERS = {
    1: {"id": 1, "owner": 1, "item": "book", "quantity": 1},
    2: {"id": 2, "owner": 2, "item": "lamp", "quantity": 2},
}
PRODUCTS = ["book", "lamp", "mug", "pen"]
# Stock per warehouse, for GET /stock (the warehouse is chosen with the X-Warehouse header).
STOCK = [("north", "book", 3), ("north", "lamp", 1), ("south", "mug", 7), ("south", "pen", 12)]
# The catalog is the same for everyone. Reading a product is not a flaw, and bola must not say so.
CATALOG = {i: {"id": i, "name": name, "price": 5 * i} for i, name in enumerate(PRODUCTS, start=1)}
# Invoices are private and correctly protected, in both lab modes.
INVOICES = {
    1: {"id": 1, "owner": 1, "order": 1, "total": 5},
    2: {"id": 2, "owner": 2, "order": 2, "total": 20},
}


# Hardened mode only: at most RATE_LIMIT requests per RATE_WINDOW seconds on a throttled route.
RATE_LIMIT = 5
RATE_WINDOW = 30.0
_recent: dict[str, list[float]] = {}  # route -> times of the latest requests
_recent_lock = threading.Lock()


def _throttled(route: str) -> float | None:
    """Count a request to `route`. Returns the seconds to wait if it is over the limit, else None."""
    now = time.monotonic()
    with _recent_lock:
        times = [t for t in _recent.get(route, []) if now - t < RATE_WINDOW]
        if len(times) >= RATE_LIMIT:
            _recent[route] = times
            return RATE_WINDOW - (now - times[0])
        _recent[route] = [*times, now]
    return None


def _public(user: dict) -> dict:
    return {k: v for k, v in user.items() if k != "password"}


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnShopLab/1"
    # HTTP/1.1 keeps a connection open between requests, so a scan doesn't reconnect every time.
    # (Every response sets Content-Length, which keep-alive needs.)
    protocol_version = "HTTP/1.1"

    # --- helpers -------------------------------------------------------------------------

    def handle_one_request(self) -> None:
        self._consumed = False  # has this request's body been read yet? (see _send)
        super().handle_one_request()

    def _send(self, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
        if not self._consumed:
            self._body()  # read any unread request body, or it would be parsed as the next request
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("X-VulnShop-Lab", "deliberately-vulnerable; local testing only")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _too_many(self, route: str) -> bool:
        # PLANTED (rate-limit): the lab never limits how often a route is called. Only the
        # hardened lab counts requests and answers 429 once a route is over its limit.
        wait = _throttled(route) if hardened() else None
        if wait is None:
            return False
        self._send(429, {"error": "too many requests"}, {"Retry-After": str(max(1, round(wait)))})
        return True

    def _caller(self) -> int | None:
        # "Authorization: Bearer <token>" -> user id, or None.
        header = self.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        return TOKENS.get(token.strip()) if scheme.lower() == "bearer" else None

    def _body(self) -> dict:
        self._consumed = True
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            self.close_connection = True  # the oversized body is left unread, so drop the connection
            return {}
        if not length:
            return {}
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _id_after(self, prefix: str, path: str) -> int | None:
        rest = path[len(prefix):]
        return int(rest) if rest.isdigit() else None

    def _lookup_user(self, username: str) -> int | None:
        """Find a user id by name, using a real (in-memory) SQLite query.

        The two modes differ only in how `username` reaches the query. The password is checked
        separately by the caller, so the planted flaw is a detectable injection point, not a way
        to log in without the password.
        """
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
            db.executemany("INSERT INTO users (id, name) VALUES (?, ?)", [(uid, u["name"]) for uid, u in USERS.items()])
            if hardened():
                # Fixed: `username` is bound as a parameter, so it is only ever data.
                rows = db.execute("SELECT id FROM users WHERE lower(name) = lower(?)", (username,)).fetchall()
            else:
                # PLANTED (injection): `username` is pasted into the query text, so a quote breaks
                # its syntax (surfacing a database error) or changes which rows it selects.
                rows = db.execute("SELECT id FROM users WHERE lower(name) = lower('" + username + "')").fetchall()
            return rows[0][0] if rows else None
        finally:
            db.close()

    def _search_products(self, q: str) -> list[str]:
        """Find products whose name contains `q`, using a real (in-memory) SQLite query.

        The query runs against a throwaway database built fresh for the request, so the lab still
        keeps no state on disk. The two modes differ only in how `q` reaches the query:
        """
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE products (name TEXT)")
            db.executemany("INSERT INTO products (name) VALUES (?)", [(name,) for name in PRODUCTS])
            if hardened():
                # Fixed: `q` is bound as a parameter, so it is only ever data, never query text.
                rows = db.execute("SELECT name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
            else:
                # PLANTED (injection): `q` is pasted straight into the query text. A `q` that closes
                # the quote changes what the query selects (boolean injection) or breaks its syntax.
                rows = db.execute("SELECT name FROM products WHERE name LIKE '%" + q + "%'").fetchall()
            return [row[0] for row in rows]
        finally:
            db.close()

    def _catalog_by_name(self, name: str) -> list[dict]:
        """Products with exactly this name, using a real (in-memory) SQLite query."""
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE products (id INTEGER, name TEXT, price INTEGER)")
            db.executemany("INSERT INTO products VALUES (?, ?, ?)", [(p["id"], p["name"], p["price"]) for p in CATALOG.values()])
            if hardened():
                rows = db.execute("SELECT id, name, price FROM products WHERE name = ?", (name,)).fetchall()
            else:
                # PLANTED (injection): the path value is pasted into the query text.
                rows = db.execute("SELECT id, name, price FROM products WHERE name = '" + name + "'").fetchall()
            return [{"id": i, "name": n, "price": p} for i, n, p in rows]
        finally:
            db.close()

    def _stock_in(self, warehouse: str) -> list[dict]:
        """Stock lines for one warehouse, using a real (in-memory) SQLite query."""
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE stock (warehouse TEXT, item TEXT, quantity INTEGER)")
            db.executemany("INSERT INTO stock VALUES (?, ?, ?)", STOCK)
            if hardened():
                rows = db.execute("SELECT item, quantity FROM stock WHERE warehouse = ?", (warehouse,)).fetchall()
            else:
                # PLANTED (injection): the X-Warehouse header is pasted into the query text.
                rows = db.execute("SELECT item, quantity FROM stock WHERE warehouse = '" + warehouse + "'").fetchall()
            return [{"item": item, "quantity": quantity} for item, quantity in rows]
        finally:
            db.close()

    # --- routes ----------------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        path = url.path

        if path == "/health":
            return self._send(200, {"status": "ok", "lab": BANNER})
        if path == "/openapi.json":
            spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
            spec["servers"] = [{"url": f"http://{self.headers.get('Host', 'localhost:8000')}"}]
            return self._send(200, spec)

        if path == "/me":
            uid = self._caller()
            if uid is None:
                return self._send(401, {"error": "login required"})
            return self._send(200, _public(USERS[uid]))

        if path == "/orders":
            uid = self._caller()
            if uid is None:
                return self._send(401, {"error": "login required"})
            return self._send(200, [o for o in ORDERS.values() if o["owner"] == uid])  # your own only

        if path == "/products" or path.startswith("/products/"):
            if self._caller() is None:
                return self._send(401, {"error": "login required"})
            if path == "/products":
                return self._send(200, list(CATALOG.values()))
            pid = self._id_after("/products/", path)
            if pid in CATALOG:
                return self._send(200, CATALOG[pid])
            return self._send(404, {"error": "no such product"})

        if path.startswith("/catalog/"):
            if self._caller() is None:
                return self._send(401, {"error": "login required"})
            name = unquote(path[len("/catalog/"):])
            try:
                found = self._catalog_by_name(name)
            except sqlite3.Error as exc:
                return self._send(500, {"error": f"SQL error: {exc}"})  # PLANTED (injection): leaks the error
            return self._send(200, found) if found else self._send(404, {"error": "no such product"})

        if path == "/stock":
            if self._caller() is None:
                return self._send(401, {"error": "login required"})
            warehouse = self.headers.get("X-Warehouse")
            if not warehouse:
                return self._send(400, {"error": "the X-Warehouse header is required"})
            try:
                return self._send(200, self._stock_in(warehouse))
            except sqlite3.Error as exc:
                return self._send(500, {"error": f"SQL error: {exc}"})  # PLANTED (injection): leaks the error

        if path.startswith("/invoices/"):
            uid = self._caller()
            if uid is None:
                return self._send(401, {"error": "login required"})
            invoice = INVOICES.get(self._id_after("/invoices/", path))
            if invoice is None or invoice["owner"] != uid:
                return self._send(404, {"error": "no such invoice"})  # not yours = not found
            return self._send(200, invoice)

        if path.startswith("/orders/"):
            if self._caller() is None:
                return self._send(401, {"error": "login required"})
            oid = self._id_after("/orders/", path)
            # PLANTED (bola): the caller must be logged in, but the order's owner is never
            # compared with the caller. Any logged-in user can read any order.
            if oid in ORDERS and hardened() and ORDERS[oid]["owner"] != self._caller():
                return self._send(404, {"error": "no such order"})  # hardened: not yours = not found
            if oid in ORDERS:
                return self._send(200, ORDERS[oid])
            return self._send(404, {"error": "no such order"})

        if path.startswith("/users/"):
            uid = self._id_after("/users/", path)
            # PLANTED (auth-required): the spec says this route needs a login, but it never checks
            # the caller's token. Anyone can read any user's profile.
            if hardened():  # fixed: a login is required, and you see only your own profile
                if self._caller() is None:
                    return self._send(401, {"error": "login required"})
                if uid != self._caller():
                    return self._send(403, {"error": "not your account"})
            if uid in USERS:
                return self._send(200, _public(USERS[uid]))
            return self._send(404, {"error": "no such user"})

        if path == "/search":
            if self._too_many("/search"):
                return None
            q = (parse_qs(url.query).get("q") or [""])[0]
            try:
                return self._send(200, self._search_products(q))
            except sqlite3.Error as exc:
                # PLANTED (injection): the raw database error is handed back to the caller. This
                # both confirms the input reached the query and leaks the engine. The hardened
                # query is parameterized, so it never reaches this branch.
                return self._send(500, {"error": f"SQL error: {exc}"})

        return self._send(404, {"error": "not found"})

    do_HEAD = do_GET  # same routes; _send skips the body for HEAD

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path

        if path == "/login":
            if self._too_many("/login"):
                return None
            data = self._body()
            try:
                uid = self._lookup_user(str(data.get("username", "")))
            except sqlite3.Error as exc:
                # PLANTED (injection): the raw database error from the user lookup is handed back
                # to the caller. The hardened lookup is parameterized, so it never errors here.
                return self._send(500, {"error": f"SQL error: {exc}"})
            if uid is not None and USERS[uid]["password"] == data.get("password"):
                token = next(t for t, owner in TOKENS.items() if owner == uid)
                return self._send(200, {"token": token})
            return self._send(401, {"error": "bad credentials"})

        if path == "/orders":
            uid = self._caller()
            if uid is None:
                return self._send(401, {"error": "login required"})
            data = self._body()
            if not isinstance(data.get("item"), str):
                return self._send(400, {"error": "item is required"})
            quantity = data.get("quantity", 1)
            if not isinstance(quantity, int) or not 1 <= quantity <= 100:
                return self._send(400, {"error": "quantity must be 1-100"})
            oid = max(ORDERS) + 1
            ORDERS[oid] = {"id": oid, "owner": uid, "item": data["item"], "quantity": quantity}
            return self._send(201, ORDERS[oid])

        return self._send(404, {"error": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path.startswith("/orders/"):
            uid = self._caller()
            if uid is None:
                return self._send(401, {"error": "login required"})
            oid = self._id_after("/orders/", path)
            if oid not in ORDERS or ORDERS[oid]["owner"] != uid:
                return self._send(404, {"error": "no such order"})  # only your own orders
            del ORDERS[oid]
            return self._send(200, {"deleted": oid})
        return self._send(404, {"error": "not found"})

    def do_PATCH(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path.startswith("/users/"):
            uid = self._caller()
            if uid is None:
                return self._send(401, {"error": "login required"})
            target = self._id_after("/users/", path)
            if target not in USERS:
                return self._send(404, {"error": "no such user"})
            if target != uid:
                return self._send(403, {"error": "not your account"})
            data = self._body()
            if hardened():
                for field in ("name", "email"):  # fixed: only the fields the spec allows
                    if isinstance(data.get(field), str):
                        USERS[target][field] = data[field]
            else:
                # PLANTED (mass-assignment): the whole body is copied onto the user record, so a
                # caller can set fields the spec never offered, such as "role".
                USERS[target].update({k: v for k, v in data.items() if k != "id"})
            return self._send(200, _public(USERS[target]))
        return self._send(404, {"error": "not found"})

    def log_message(self, fmt: str, *args: object) -> None:
        # One short line per request on stdout, visible with `docker compose logs`.
        print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else '?'}", flush=True)


if __name__ == "__main__":
    if os.environ.get("DEMO_MODE") != "1":
        sys.exit("refusing to start: VulnShop is deliberately vulnerable. Set DEMO_MODE=1 to run it locally.")
    print(BANNER + (" (hardened: no planted flaws)" if hardened() else ""), flush=True)
    port = int(os.environ.get("PORT", "8000"))
    # 0.0.0.0 inside the container is required for Docker to forward to it. docker-compose.yml
    # publishes the port on 127.0.0.1 only, so the lab is not reachable from your network.
    # Running outside Docker? Set HOST=127.0.0.1 so it only listens on loopback.
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"VulnShop lab listening on {host}:{port}", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
