"""Check: does an update endpoint save fields the caller should not be able to set?

This is OWASP API3 (Broken Object Property Level Authorization), better known as mass
assignment. The spec says PATCH /users/{id} takes `name` and `email`, but the code copies the
whole request body onto the user record, so a caller who also sends `role` gets it saved.

How the check works, on one of test account A's own objects:

1. Read the object (GET on the same path). Its fields that the spec does NOT list as writable
   are the candidates, e.g. `role`. If none of those sticks, a few common hidden names are
   tried as well (`role`, `is_admin`, `verified`).
2. Send the update with exactly one extra field set to a probe value, then read the object back.
   One field per request keeps the result easy to understand.
3. If the read-back shows the probe value, and a second read confirms it, the field is writable
   when it should not be: a finding.
4. Put the original value back, and read once more to make sure. The finding says whether that
   worked.

The probe proves the flaw without using it. A text field such as `role` is set to the marker
"apifuzz-probe", never to "admin", so the test account gains nothing. A true/false field is
flipped and a number is raised by one, both only until step 4 restores them.

Left alone on purpose, because a change there could not be undone safely:
  - ids, owner fields and timestamps (changing an owner would hand the object to someone else)
  - passwords, tokens and other secrets

Create endpoints (POST /orders) are probed only when the spec also has DELETE /orders/{id}, so
every object the check creates can be removed again: one plain object to learn the fields, then
one per extra field, each deleted straight after it is read. Without a DELETE the endpoint is
listed as not tested, because the test data could not be cleaned up.

Severity: CRITICAL for a field that controls what the user may do (role, is_admin, verified...),
HIGH for any other field the spec doesn't list as writable.
"""

import json
from collections.abc import Iterator

from apifuzz.checks.base import NOT_TESTED, TESTED, Check, ScanContext, fill_path, sample_body
from apifuzz.checks.bola import _as_id, own_id
from apifuzz.endpoint_model import Endpoint
from apifuzz.finding import Finding, Severity
from apifuzz.http_client import Exchange

PROBE_TEXT = "apifuzz-probe"  # the marker written into text fields
_MAX_FIELDS = 6  # fields of the object tried per endpoint
_MAX_CREATE_FIELDS = 3  # on create endpoints every try makes (and deletes) an object, so fewer
_HIDDEN_GUESSES = ("role", "is_admin", "verified")  # tried only when no real field sticks
_MISSING = object()  # "the object has no such field", as opposed to a field that is null

# Field names (lower case, underscores removed) that decide what a user is allowed to do.
_PRIVILEGE = {
    "role", "roles", "admin", "isadmin", "isstaff", "superuser", "issuperuser", "permissions", "scope", "scopes",
    "verified", "isverified", "emailverified", "active", "isactive", "plan", "tier", "group", "groups",
}
# Parts of a field name that mean "do not touch": identity, ownership, time stamps, secrets.
_UNTOUCHABLE_PARTS = (
    "owner", "user", "tenant", "account", "created", "updated", "modified", "deleted", "date",
    "password", "passwd", "secret", "token", "key", "hash", "salt",
)
def _norm(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")


def _is_privilege(name: str) -> bool:
    return _norm(name) in _PRIVILEGE


def _probeable(name: str, value: object) -> bool:
    """True if the field can be changed and put back safely (see the module docstring)."""
    lower = name.lower()
    if lower == "id" or lower.endswith("_id") or name.endswith("Id") or lower.endswith("_at"):
        return False
    if any(part in lower for part in _UNTOUCHABLE_PARTS):
        return False
    return value is None or isinstance(value, (str, bool, int, float))


def _probe_value(original: object) -> object:
    """A value that differs from the original, but grants as little as possible."""
    if isinstance(original, bool):
        return not original
    if isinstance(original, (int, float)):
        return original + 1
    return PROBE_TEXT


def _object(exchange: Exchange) -> dict | None:
    if not exchange.response.ok:
        return None
    try:
        body = json.loads(exchange.response.body)
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


class MassAssignment(Check):
    id = "mass-assignment"
    owasp = "API3:2023 Broken Object Property Level Authorization"
    description = "An update must not save fields the spec doesn't list as writable, such as role (needs one account)."

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> Iterator[Finding]:
        if endpoint.method not in ("PATCH", "PUT", "POST") or not endpoint.requires_auth or not endpoint.request_fields:
            return
        headers = ctx.auth("a")
        if not headers:
            ctx.record(self.id, endpoint, NOT_TESTED, "needs a test account")
            return
        if endpoint.method == "POST":
            yield from self._run_create(endpoint, ctx, headers)
            return
        path_params = [p for p in endpoint.parameters if p.location == "path"]
        if len(path_params) > 1:
            ctx.record(self.id, endpoint, NOT_TESTED, "has more than one path parameter (not supported yet)")
            return
        if not any(e.method == "GET" and e.path == endpoint.path for e in ctx.endpoints):
            ctx.record(self.id, endpoint, NOT_TESTED, "has no GET on the same path to read the object back")
            return

        values: dict[str, str] = {}
        if path_params:
            param = path_params[0]
            object_id = own_id(ctx, endpoint, param.name)
            if object_id is None or (param.type in ("integer", "number") and not object_id.isdigit()):
                ctx.record(self.id, endpoint, NOT_TESTED, "no object of the test account is known for it")
                return
            values[param.name] = object_id
        url = ctx.url(fill_path(endpoint, values))

        def read() -> dict | None:
            return _object(ctx.client.request("GET", url, headers=headers))

        before = read()
        if before is None:
            ctx.record(self.id, endpoint, NOT_TESTED, "the object could not be read before changing it")
            return

        declared = {f.name for f in endpoint.request_fields}
        present = [k for k, v in before.items() if k not in declared and _probeable(k, v)]
        present.sort(key=lambda k: not _is_privilege(k))  # privilege fields first (stable sort)
        hidden = [n for n in _HIDDEN_GUESSES if n not in before and n not in declared]

        found = False
        ctx.record(self.id, endpoint, TESTED)
        for field in [*present[:_MAX_FIELDS], *hidden]:
            if found and field in hidden:
                break  # a real field already stuck; guessing hidden names would only add noise
            original = before.get(field, _MISSING)
            probe = _probe_value(None if original is _MISSING else original)
            # PATCH changes only what it is given; PUT replaces the object, so send it back whole.
            body = {field: probe} if endpoint.method == "PATCH" else {**before, field: probe}
            write = ctx.client.request(endpoint.method, url, headers=headers, json=body)
            if not write.response.ok:
                continue  # refused: what a correct API does with a field it doesn't accept
            readback = ctx.client.request("GET", url, headers=headers)
            after = _object(readback) or {}
            if after.get(field, _MISSING) != probe:
                continue  # accepted but not saved: the field was ignored
            confirm = _object(ctx.client.request("GET", url, headers=headers)) or {}
            confirmed = confirm.get(field, _MISSING) == probe

            # Put things back the way they were, whether or not the result is reported.
            restore_value = None if original is _MISSING else original
            restore_body = {field: restore_value} if endpoint.method == "PATCH" else dict(before)
            restore = ctx.client.request(endpoint.method, url, headers=headers, json=restore_body)
            final = read() or {}
            restored = final.get(field, _MISSING) == original or (original is _MISSING and final.get(field) is None)
            if not confirmed:
                continue  # not reproducible; don't report a flaky result

            found = True
            privilege = _is_privilege(field)
            was = "did not exist" if original is _MISSING else f"was {json.dumps(original)}"
            cleanup = (
                "The original value was put back afterwards."
                if restored
                else f"The original value could NOT be put back: set {field!r} on this object by hand."
            )
            yield Finding(
                check=self.id,
                owasp=self.owasp,
                severity=Severity.CRITICAL if privilege else Severity.HIGH,
                title=f"Field {field!r} can be set by the caller (mass assignment)",
                endpoint=f"{endpoint.method} {endpoint.path}",
                key=field,
                detail=(
                    f"The spec does not list {field!r} as a writable field, but sending it in the update "
                    f"saved it: it {was}, and the object read back showed {json.dumps(probe)} (confirmed "
                    f"on a second read). "
                    + ("This field controls what the user may do, so a caller can raise their own privileges. " if privilege else "")
                    + cleanup
                ),
                remediation=(
                    "Copy only the fields the endpoint is meant to accept from the request onto the object "
                    "(an explicit allowlist or a dedicated input model), and ignore or reject everything else. "
                    "Never bind the whole request body to the stored record."
                ),
                evidence=[write, readback, restore],
            )

    def _run_create(self, endpoint: Endpoint, ctx: ScanContext, headers: dict[str, str]) -> Iterator[Finding]:
        """Mass assignment on a create endpoint. Every object created here is deleted again."""
        if "{" in endpoint.path:
            ctx.record(self.id, endpoint, NOT_TESTED, "is a create endpoint under a path parameter (not supported yet)")
            return
        base = endpoint.path.rstrip("/")
        # The single-object path, e.g. "/orders/{id}": it must offer DELETE (cleanup) and GET (read-back).
        item = [e for e in ctx.endpoints if e.path.startswith(base + "/{") and e.path.endswith("}") and e.path.count("{") == 1]
        deleter = next((e for e in item if e.method == "DELETE"), None)
        reader = next((e for e in item if e.method == "GET"), None)
        if deleter is None or reader is None:
            ctx.record(
                self.id, endpoint, NOT_TESTED,
                "has no DELETE and GET for the created object, so test data could not be cleaned up",
            )
            return
        param = next(p.name for p in deleter.parameters if p.location == "path")
        url = ctx.url(endpoint.path)
        leftovers: list[str] = []

        def create(extra: dict[str, object]) -> tuple[Exchange, dict | None, str | None]:
            ex = ctx.client.request("POST", url, headers=headers, json={**sample_body(endpoint), **extra})
            created = _object(ex)
            return ex, created, _as_id((created or {}).get("id"))

        def remove(object_id: str) -> Exchange:
            ex = ctx.client.request("DELETE", ctx.url(fill_path(deleter, {param: object_id})), headers=headers)
            if not ex.response.ok:
                leftovers.append(object_id)
            return ex

        _, plain, plain_id = create({})
        if plain is None or plain_id is None:
            ctx.record(self.id, endpoint, NOT_TESTED, "a plain create did not answer with an object that has an id")
            return
        remove(plain_id)

        declared = {f.name for f in endpoint.request_fields}
        present = [k for k, v in plain.items() if k not in declared and _probeable(k, v)]
        present.sort(key=lambda k: not _is_privilege(k))
        hidden = [n for n in _HIDDEN_GUESSES if n not in plain and n not in declared]
        ctx.record(self.id, endpoint, TESTED)
        for field in [*present, *hidden][:_MAX_CREATE_FIELDS]:
            original = plain.get(field, _MISSING)
            probe = _probe_value(None if original is _MISSING else original)
            write, _, object_id = create({field: probe})
            if object_id is None:
                continue  # refused, or no object came back: nothing was created to look at
            readback = ctx.client.request("GET", ctx.url(fill_path(reader, {param: object_id})), headers=headers)
            cleanup = remove(object_id)
            if (_object(readback) or {}).get(field, _MISSING) != probe:
                continue  # the extra field was ignored
            privilege = _is_privilege(field)
            was = "is not normally there" if original is _MISSING else f"is normally {json.dumps(original)}"
            yield Finding(
                check=self.id,
                owasp=self.owasp,
                severity=Severity.CRITICAL if privilege else Severity.HIGH,
                title=f"Field {field!r} can be set by the caller on create (mass assignment)",
                endpoint=f"{endpoint.method} {endpoint.path}",
                key=field,
                detail=(
                    f"The spec does not list {field!r} as a field of the create request, but sending it "
                    f"saved it: it {was}, and the new object read back showed {json.dumps(probe)}. "
                    + ("This field controls what the user may do. " if privilege else "")
                    + (
                        "The object created for this test was deleted again."
                        if cleanup.response.ok
                        else f"The object created for this test (id {object_id}) could NOT be deleted: remove it by hand."
                    )
                ),
                remediation=(
                    "Build the new object only from the fields the endpoint is meant to accept (an explicit "
                    "allowlist or a dedicated input model), and set everything else on the server."
                ),
                evidence=[write, readback, cleanup],
            )
        if leftovers:
            ctx.leftovers.append(
                f"{endpoint.method} {endpoint.path}: test objects could not be deleted, ids {', '.join(leftovers)}"
            )
