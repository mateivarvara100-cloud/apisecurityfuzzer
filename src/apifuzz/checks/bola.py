"""Check: can one logged-in user read another user's objects? (BOLA/IDOR, OWASP API1.)

Broken Object Level Authorization means an endpoint like GET /orders/{id} checks that you are
logged in but not that the order is yours. The check uses two test accounts, A and B (token
swapping):

1. Recon: once per scan, call the protected GET endpoints that take no path parameter (e.g.
   /me, /orders) as A and as B, and note which ids appear in each account's answers, and on
   which endpoint. Those real ids are the candidates; for numeric ids, 1-5 are added as guesses.
2. Cross-access: every candidate is requested as A and as B, so both directions are covered.
   If the API enforces ownership, each object answers 2xx for at most one account.
3. Same object: the two answers must be the same object. An API that answers 200 with an error
   message to the wrong user is not leaking anything.
4. Guard: an object both accounts can read is requested with no token. If that also succeeds,
   the endpoint is simply unauthenticated: the auth-required check's finding, not BOLA.
5. Confirmation: B's request is repeated. Only a reproducible result is reported.

Severity follows how strong the evidence is that the object belongs to one user:
  CRITICAL  proven: the id is listed in only one account's own collection (GET /orders shows it
            to A and not to B), yet both could read it at GET /orders/{id}.
  HIGH      likely: the object has an owner field (owner, user_id...). That shows who made it,
            not that it is private; a public post names its author too.
  LOW       not proven: both accounts can read it and nothing says whose it is.
An object that the API itself lists to both accounts is shared by design and is not reported
(unless it has an owner field). Paths the user marks as shared (--shared) are skipped.

Ids are attributed per collection: an id seen in /orders proves ownership only for /orders/{id},
never for /products/{id}, where the same number is a different object.

Nested paths such as /users/{userId}/orders/{orderId} are probed on the last id. The ids before
it are filled with account A's own (its user id from /me, say), so the question becomes "can B
read an object under A's part of the tree?". The listing is then GET /users/{A}/orders.

Limits: only read-only GET endpoints, and at most _MAX_IDS candidate ids. Recon sends only GET requests, so it changes nothing on the target.
"""

import json
import re
from collections.abc import Iterator
from fnmatch import fnmatchcase

from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext, fill_path
from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import RequestError
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Exchange
from apifuzz.session_manager import IDENTITY_NAMES

_GUESS_IDS = ("1", "2", "3", "4", "5")  # small ids a test system is likely to hold
_MAX_IDS = 12  # cap on candidate ids per endpoint, so the check stays a handful of requests
# Response fields that say "this object belongs to a particular user".
_OWNER_FIELDS = {
    "owner", "owner_id", "ownerid", "user_id", "userid", "account_id", "accountid", "customer_id", "customerid",
}
# A string id we are willing to put in a URL: a UUID, a slug, a number. Nothing with spaces or slashes.
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

_REMEDIATION = (
    "Before returning an object, check that it belongs to the caller (or that the caller is "
    "allowed to see it), and answer 403 or 404 otherwise. Looking objects up through the caller "
    "(e.g. WHERE id = ? AND owner_id = current_user) makes the check hard to forget."
)

Ids = tuple[set[str], set[str]]  # (ids seen by account A, ids seen by account B)


def _json(exchange: Exchange) -> object:
    try:
        return json.loads(exchange.response.body)
    except ValueError:
        return None


def _has_owner_field(exchange: Exchange) -> bool:
    """True if the JSON body is an object with an owner-like key, e.g. {"owner": 2}."""
    body = _json(exchange)
    return isinstance(body, dict) and any(k.lower() in _OWNER_FIELDS for k in body)


def _same_object(as_a: Exchange, as_b: Exchange) -> bool:
    """True if both accounts received the same object, not just the same status code.

    Identical bodies count. So do two JSON objects that agree on most of their fields, since an
    API may add a per-viewer field such as "is_mine". An empty body gives nothing away.
    """
    a, b = _json(as_a), _json(as_b)
    if a is None or b is None:
        text = as_a.response.body.strip()
        return text not in ("", "null") and text == as_b.response.body.strip()
    if a == b:
        return a not in ({}, [], "")
    if isinstance(a, dict) and isinstance(b, dict):
        same = sum(1 for key in a.keys() & b.keys() if a[key] == b[key])
        return same >= 1 and same * 2 >= len(a.keys() | b.keys())
    return False


def _as_id(value: object) -> str | None:
    """An id value as text, or None if it isn't one: a positive whole number or a short safe string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if 0 < value < 10**12 else None
    if isinstance(value, str) and _SAFE_ID.match(value):
        return value
    return None


def _is_id_key(key: str) -> bool:
    k = key.lower()
    return k == "id" or k.endswith("_id") or key.endswith("Id")  # id, order_id, orderId


def _ids_in(value: object, wanted=_is_id_key, depth: int = 0) -> set[str]:
    """Id values (as text) under keys accepted by `wanted`, looking two levels deep."""
    found: set[str] = set()
    if depth > 2:
        return found
    if isinstance(value, list):
        for item in value[:50]:
            found |= _ids_in(item, wanted, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                found |= _ids_in(item, wanted, depth + 1)
            elif wanted(key) and (text := _as_id(item)):
                found.add(text)
    return found


def _recon(ctx: ScanContext) -> dict[str, tuple[object, object]]:
    """Once per scan: each parameterless protected GET's JSON answer for A and for B, by path."""
    if "bola_recon" not in ctx.cache:
        seen: dict[str, tuple[object, object]] = {}
        for e in ctx.endpoints:
            if e.method != "GET" or not e.requires_auth or "{" in e.path:
                continue
            if any(p.required and p.location in ("path", "query") for p in e.parameters):
                continue  # we'd have to invent a value; skip it
            answers: list[object] = []
            for account in ("a", "b"):
                if not ctx.auth(account):
                    answers.append(None)  # no such test account: nothing to ask as
                    continue
                try:
                    ex = ctx.client.request("GET", ctx.url(e.path), headers=ctx.auth(account))
                except RequestError:
                    answers.append(None)  # recon is best-effort; the probes themselves still run
                    continue
                answers.append(_json(ex) if ex.response.ok else None)
            seen[e.path.rstrip("/") or "/"] = (answers[0], answers[1])
        ctx.cache["bola_recon"] = seen
    return ctx.cache["bola_recon"]  # type: ignore[return-value]


def _collection(endpoint: Endpoint, name: str) -> str:
    """The path that lists this endpoint's objects: "/orders/{id}" -> "/orders"."""
    return endpoint.path.split("{" + name + "}", 1)[0].rstrip("/") or "/"


def _listed(recon: dict[str, tuple[object, object]], collection: str, name: str) -> Ids | None:
    """Ids each account sees in its own listing of this collection, or None if there is no listing."""
    if collection not in recon:
        return None
    own = name.lower().replace("_", "")  # "order_id" and "orderId" both become "orderid"

    def wanted(key: str) -> bool:
        return key.lower().replace("_", "") in ("id", own)

    answer_a, answer_b = recon[collection]
    if answer_a is None or answer_b is None:
        return None  # one listing is missing, so "only A lists it" can't be claimed
    return _ids_in(answer_a, wanted), _ids_in(answer_b, wanted)


# Collections whose objects are the users themselves: there, "my object" is the caller's own id.
_USER_COLLECTIONS = {"users", "user", "accounts", "account", "profiles", "members", "customers"}


def own_id(ctx: ScanContext, endpoint: Endpoint, name: str) -> str | None:
    """The id of an object that belongs to test account A, for path parameter `name`."""
    recon = _recon(ctx)
    collection = _collection(endpoint, name)
    own = name.lower().replace("_", "")
    listing = recon.get(collection, (None, None))[0]  # what account A sees at e.g. GET /orders
    ids = sorted(_ids_in(listing, lambda key: key.lower().replace("_", "") in ("id", own))) if listing is not None else []
    if ids:
        return ids[0]
    if collection.rsplit("/", 1)[-1].lower() in _USER_COLLECTIONS:
        # /users/{id}: the caller's own id, from a "who am I" endpoint such as GET /me.
        for path, (answer, _) in recon.items():
            if path.rsplit("/", 1)[-1].lower() in IDENTITY_NAMES and isinstance(answer, dict):
                if found := _as_id(answer.get("id")):
                    return found
    return None


def _nested_listing(ctx: ScanContext, endpoint: Endpoint, name: str, values: dict[str, str]) -> Ids | None:
    """For a nested path: the ids A and B see at the listing under A's own parent ids.

    For /users/{userId}/orders/{orderId} with userId = A's id, that is GET /users/<A>/orders.
    B being refused there (401/403/404) counts as "B is shown none of them".
    """
    template = _collection(endpoint, name)
    lister = next((e for e in ctx.endpoints if e.method == "GET" and e.path.rstrip("/") == template), None)
    if lister is None:
        return None
    own = name.lower().replace("_", "")
    url = ctx.url(fill_path(lister, values))
    seen: list[set[str]] = []
    for account in ("a", "b"):
        try:
            ex = ctx.client.request("GET", url, headers=ctx.auth(account))
        except RequestError:
            return None
        if ex.response.ok:
            seen.append(_ids_in(_json(ex), lambda key: key.lower().replace("_", "") in ("id", own)))
        elif account == "b" and ex.response.status_code in (401, 403, 404):
            seen.append(set())
        else:
            return None
    return seen[0], seen[1]


class Bola(Check):
    id = "bola"
    owasp = "API1:2023 Broken Object Level Authorization"
    description = "One user must not be able to read another user's object by changing its id (needs two accounts)."

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        path_params = [p for p in endpoint.parameters if p.location == "path"]
        # Only read-only requests are safe to repeat as another user.
        if endpoint.method != "GET" or not endpoint.requires_auth or not path_params:
            return
        headers_a, headers_b = ctx.auth("a"), ctx.auth("b")
        if not headers_a or not headers_b:
            ctx.record(self.id, endpoint, NOT_TESTED, "needs two test accounts")
            return
        if any(fnmatchcase(endpoint.path, pattern) for pattern in ctx.settings.shared_paths):
            ctx.record(self.id, endpoint, NOT_TESTED, "marked as shared on purpose (--shared)")
            return
        # The last id in the path is the one probed; any ids before it are account A's own.
        path_params.sort(key=lambda p: endpoint.path.find("{" + p.name + "}"))
        *parents, target = path_params
        name = target.name
        numeric = target.type in ("integer", "number")
        recon = _recon(ctx)
        values: dict[str, str] = {}
        for parent in parents:
            mine = own_id(ctx, endpoint, parent.name)
            if mine is None:
                ctx.record(self.id, endpoint, NOT_TESTED, f"no id of test account A is known for {{{parent.name}}}")
                return
            values[parent.name] = mine
        if parents:
            listed = _nested_listing(ctx, endpoint, name, values)
        else:
            listed = _listed(recon, _collection(endpoint, name), name)
        own_a, own_b = listed or (set(), set())
        everything = set().union(*(_ids_in(answer) for pair in recon.values() for answer in pair))
        # Ids that only one account lists come first: they are the ones that can prove ownership.
        ordered = [*sorted(own_a ^ own_b), *sorted(own_a & own_b), *sorted(everything)]
        if numeric:
            ordered = [i for i in ordered if i.isdigit()] + list(_GUESS_IDS)  # guessing only works for numbers
        candidates = list(dict.fromkeys(ordered))[:_MAX_IDS]
        if not candidates:
            ctx.record(self.id, endpoint, NOT_TESTED, "no real id is known for it, and its ids can't be guessed")
            return

        readable = False  # did any candidate answer 2xx to at least one account?
        for object_id in candidates:
            url = ctx.url(fill_path(endpoint, {**values, name: object_id}))
            as_a = ctx.client.request("GET", url, headers=headers_a)
            as_b = ctx.client.request("GET", url, headers=headers_b)
            readable = readable or as_a.response.ok or as_b.response.ok
            if not (as_a.response.ok and as_b.response.ok):
                continue  # readable by one account or neither: what a correct API does
            if not _same_object(as_a, as_b):
                continue  # two different answers (e.g. a 200 that carries an error): nothing leaked

            anonymous = ctx.client.request("GET", url)
            if anonymous.response.ok:
                break  # open to everyone: auth-required reports that, not BOLA
            confirm = ctx.client.request("GET", url, headers=headers_b)
            if not confirm.response.ok:
                continue  # not reproducible; don't report a flaky result

            in_a, in_b = object_id in own_a, object_id in own_b
            if in_a != in_b:
                who, other = ("A", "B") if in_a else ("B", "A")
                severity, title = Severity.CRITICAL, "One user can read another user's object"
                note = (
                    f"GET {_collection(endpoint, name)} lists this id only for account {who}, "
                    f"yet account {other} could read it."
                )
                fix = _REMEDIATION
            elif _has_owner_field(as_a):
                severity, title = Severity.HIGH, "Object with an owner field is readable by both test accounts"
                note = (
                    "The object names an owner, so it likely belongs to one user. This is not proof: "
                    "an object can name its author and still be public. If it is meant to be shared, "
                    "mark the path with --shared."
                )
                fix = _REMEDIATION
            elif in_a and in_b:
                continue  # the API itself lists it to both accounts: shared by design
            else:
                severity, title = Severity.LOW, "Object readable by both test accounts (ownership not proven)"
                note = "Nothing shows it belongs to one user, so it may be shared on purpose. Review it."
                fix = (
                    "If the object belongs to one user, check that it belongs to the caller before "
                    "returning it and answer 403 or 404 otherwise. If it is meant to be shared, no "
                    "change is needed; mark the path with --shared to stop this note."
                )
            ctx.record(self.id, endpoint, TESTED)
            yield Finding(
                check=self.id,
                owasp=self.owasp,
                severity=severity,
                title=title,
                endpoint=f"{endpoint.method} {endpoint.path}",
                detail=(
                    f"Object {name}={object_id} gave the same answer to test account A and test account B "
                    f"(confirmed on a second request), while a request without a token was refused. {note}"
                ),
                remediation=fix,
                evidence=[as_a, as_b, anonymous, confirm],
            )
            return  # one finding per endpoint is enough

        if readable:
            ctx.record(self.id, endpoint, TESTED)
        else:
            ctx.record(
                self.id, endpoint, NOT_TESTED,
                f"neither account could read any of the {len(candidates)} ids tried, so there was nothing to compare",
            )
