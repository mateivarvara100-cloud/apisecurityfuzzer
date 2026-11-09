"""Check: can one logged-in user read another user's objects? (BOLA/IDOR, OWASP API1.)

Broken Object Level Authorization means an endpoint like GET /orders/{id} checks that you are
logged in but not that the order is yours. The check uses two test accounts, A and B (token
swapping):

1. Recon: once per scan, call the protected GET endpoints that take no path parameter (e.g.
   /me, /orders) as A and as B, and note which ids appear in each account's own answers.
   Those real ids, plus the small ids 1-5, are the candidates.
2. Cross-access: every candidate is requested as A and as B, so both directions are covered.
   If the API enforces ownership, each object answers 2xx for at most one account.
3. Guard: an object both accounts can read is requested with no token. If that also succeeds,
   the endpoint is simply unauthenticated: the auth-required check's finding, not BOLA.
4. Confirmation: B's request is repeated. Only a reproducible result is reported.

Severity follows the evidence that the object belongs to one user:
  CRITICAL  proven: the object has an owner field (owner, user_id...), or recon saw its id in
            only one account's own data, so the other account read something that isn't theirs.
  LOW       not proven: both accounts can read it, but it may be shared on purpose (a public
            profile, a product). Reported so a person can review it.

Limits: only read-only GET endpoints with exactly one integer path parameter, and at most
_MAX_IDS candidate ids. Recon sends only GET requests, so it changes nothing on the target.
"""

import json
from collections.abc import Iterator

from apifuzz.checks.base import Check, ScanContext, fill_path
from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import RequestError
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Exchange

_GUESS_IDS = (1, 2, 3, 4, 5)  # small ids a test system is likely to hold
_MAX_IDS = 12  # cap on candidate ids per endpoint, so the check stays a handful of requests
# Response fields that say "this object belongs to a particular user".
_OWNER_FIELDS = {"owner", "owner_id", "ownerid", "user_id", "userid", "account_id", "accountid", "customer_id", "customerid"}

_REMEDIATION = (
    "Before returning an object, check that it belongs to the caller (or that the caller is "
    "allowed to see it), and answer 403 or 404 otherwise. Looking objects up through the caller "
    "(e.g. WHERE id = ? AND owner_id = current_user) makes the check hard to forget."
)


def _has_owner_field(exchange: Exchange) -> bool:
    """True if the JSON body is an object with an owner-like key, e.g. {"owner": 2}."""
    try:
        body = json.loads(exchange.response.body)
    except ValueError:
        return False
    return isinstance(body, dict) and any(k.lower() in _OWNER_FIELDS for k in body)


def _is_id_key(key: str) -> bool:
    k = key.lower()
    return k == "id" or k.endswith("_id") or key.endswith("Id")  # id, order_id, orderId


def _ids_in(value: object, depth: int = 0) -> set[int]:
    """Positive integer values of id-like keys in a JSON value, looking two levels deep."""
    found: set[int] = set()
    if depth > 2:
        return found
    if isinstance(value, list):
        for item in value[:50]:
            found |= _ids_in(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if _is_id_key(key) and isinstance(item, int) and not isinstance(item, bool) and 0 < item < 10**12:
                found.add(item)
            elif isinstance(item, (dict, list)):
                found |= _ids_in(item, depth + 1)
    return found


def _recon(ctx: ScanContext, headers_a: dict[str, str], headers_b: dict[str, str]) -> tuple[set[int], set[int]]:
    """Once per scan: the ids in A's own answers and in B's own answers from parameterless GETs."""
    if "bola_recon" not in ctx.cache:
        seen: tuple[set[int], set[int]] = (set(), set())
        for e in ctx.endpoints:
            if e.method != "GET" or not e.requires_auth or "{" in e.path:
                continue
            if any(p.required and p.location in ("path", "query") for p in e.parameters):
                continue  # we'd have to invent a value; skip it
            for ids, headers in zip(seen, (headers_a, headers_b)):
                try:
                    ex = ctx.client.request("GET", ctx.url(e.path), headers=headers)
                except RequestError:
                    continue  # recon is best-effort; the probes themselves still run
                if ex.response.ok:
                    try:
                        ids |= _ids_in(json.loads(ex.response.body))
                    except ValueError:
                        pass
        ctx.cache["bola_recon"] = seen
    return ctx.cache["bola_recon"]  # type: ignore[return-value]


class Bola(Check):
    id = "bola"
    owasp = "API1:2023 Broken Object Level Authorization"
    description = "One user must not be able to read another user's object by changing its id (needs two accounts)."

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        token_a, token_b = ctx.settings.token_a, ctx.settings.token_b
        if not token_a or not token_b:
            return  # needs both accounts; the CLI tells the user when they are missing
        path_params = [p for p in endpoint.parameters if p.location == "path"]
        if (
            endpoint.method != "GET"  # only read-only requests are safe to repeat as another user
            or not endpoint.requires_auth
            or len(path_params) != 1
            or path_params[0].type not in ("integer", "number")  # we can only guess numeric ids
        ):
            return

        name = path_params[0].name
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}
        ids_a, ids_b = _recon(ctx, headers_a, headers_b)
        candidates = list(dict.fromkeys([*sorted(ids_a | ids_b), *_GUESS_IDS]))[:_MAX_IDS]  # real ids first

        for object_id in candidates:
            url = ctx.url(fill_path(endpoint, {name: str(object_id)}))
            as_a = ctx.client.request("GET", url, headers=headers_a)
            as_b = ctx.client.request("GET", url, headers=headers_b)
            if not (as_a.response.ok and as_b.response.ok):
                continue  # readable by one account or neither: what a correct API does

            anonymous = ctx.client.request("GET", url)
            if anonymous.response.ok:
                return  # open to everyone: auth-required reports that, not BOLA
            confirm = ctx.client.request("GET", url, headers=headers_b)
            if not confirm.response.ok:
                continue  # not reproducible; don't report a flaky result

            # Evidence that the object belongs to one user only.
            proof = None
            if _has_owner_field(as_a):
                proof = "The response has an owner field, so the object belongs to one user."
            elif (object_id in ids_a) != (object_id in ids_b):
                who, other = ("A", "B") if object_id in ids_a else ("B", "A")
                proof = f"Recon found this id only in account {who}'s own data, yet account {other} could read it."

            if proof:
                severity, title = Severity.CRITICAL, "One user can read another user's object"
                note, fix = proof, _REMEDIATION
            else:
                severity, title = Severity.LOW, "Object readable by both test accounts (ownership not proven)"
                note = "Nothing shows it belongs to one user, so it may be shared on purpose. Review it."
                fix = (
                    "If the object belongs to one user, check that it belongs to the caller before "
                    "returning it and answer 403 or 404 otherwise. If it is meant to be shared, no change is needed."
                )
            yield Finding(
                check=self.id,
                owasp=self.owasp,
                severity=severity,
                title=title,
                endpoint=f"{endpoint.method} {endpoint.path}",
                detail=(
                    f"Object {name}={object_id} answered 2xx to both test account A and test account B "
                    f"(confirmed on a second request), while a request without a token was refused. {note}"
                ),
                remediation=fix,
                evidence=[as_a, as_b, anonymous, confirm],
            )
            return  # one finding per endpoint is enough
