"""Flatten a resolved OpenAPI/Swagger document into a list of Endpoint objects.

Input: the spec as a Python dict, with every $ref already filled in (spec_loader does that).
Output: one Endpoint per path + method pair, e.g. GET /orders/{id}.
The security checks in later phases read these Endpoints to decide which requests to send.
"""

from typing import Any  # type hint meaning "any value" (a spec can contain anything)

from pydantic import BaseModel  # gives classes typed fields, validation, and free JSON output

# The only keys in a path item that are operations. Other keys live next to them
# ("parameters", "summary", "x-something") and must not be mistaken for HTTP methods.
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class Parameter(BaseModel):
    """A value sent outside the request body: in the URL path, query string, a header or a cookie."""

    name: str  # e.g. "id" or "q"
    location: str  # "path", "query", "header" or "cookie" (copied from the spec's "in" field)
    required: bool = False  # class default only; _to_parameter always passes the real value
    type: str | None = None  # e.g. "integer"; None when the spec doesn't say


class RequestField(BaseModel):
    """One top-level field of a request body (a JSON property or a form field)."""

    name: str  # e.g. "username"
    required: bool = False  # True if the body schema lists this name under "required"
    type: str | None = None  # e.g. "string", "array[integer]", "object"


class Endpoint(BaseModel):
    """Everything the scanner needs to know about one operation, e.g. PATCH /users/{id}."""

    path: str  # the URL template, placeholders included: "/orders/{id}"
    method: str  # upper case: GET, POST...
    operation_id: str | None = None  # the spec's optional unique name for the operation
    summary: str | None = None  # the spec's optional one-line description
    parameters: list[Parameter] = []  # path/query/header/cookie values (pydantic copies this default safely)
    request_fields: list[RequestField] = []  # fields of the request body, if it has one
    requires_auth: bool = False  # True if a login token must be sent
    tags: list[str] = []  # the spec's grouping labels, e.g. ["orders"]; used by --tag
    deprecated: bool = False  # the spec marks this operation as deprecated


def build_endpoints(spec: dict[str, Any]) -> list[Endpoint]:
    """List every operation in `spec`, in the order the spec declares them.

    `spec` must already have its $refs resolved (see spec_loader.load_spec).
    """
    endpoints: list[Endpoint] = []
    # spec["paths"] maps each URL template to a "path item": {"/orders/{id}": {"get": {...}}}.
    # `or {}` covers a spec where "paths" is present but empty (None).
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):  # skip anything malformed instead of crashing
            continue
        # Parameters declared on the path itself apply to every method under that path.
        shared_params = path_item.get("parameters") or []
        for method in HTTP_METHODS:
            operation = path_item.get(method)  # None if this path doesn't support this method
            if not isinstance(operation, dict):
                continue
            # Combine the path's shared parameters with the operation's own ones.
            parameters = _merge_parameters(shared_params, operation.get("parameters") or [])
            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary"),
                    # "body" and "formData" are Swagger 2's way of describing the request body.
                    # They are body content, not URL parameters, so _request_fields handles them.
                    parameters=[_to_parameter(p) for p in parameters if p.get("in") not in ("body", "formData")],
                    request_fields=_request_fields(operation, parameters),
                    requires_auth=_requires_auth(operation, spec),
                    tags=[str(t) for t in operation.get("tags") or []],
                    deprecated=bool(operation.get("deprecated", False)),
                )
            )
    return endpoints


def _merge_parameters(path_level: list[dict], operation_level: list[dict]) -> list[dict]:
    # A parameter is identified by (name, location); the operation's version wins over the path's.
    merged: dict[tuple[str, str], dict] = {}
    # Path-level ones go in first, operation-level ones second. Writing to a dict key that
    # already exists replaces the old value, so the operation's version wins.
    for param in [*path_level, *operation_level]:
        if isinstance(param, dict) and "name" in param:  # ignore malformed entries
            merged[(param["name"], param.get("in", ""))] = param
    return list(merged.values())


def _to_parameter(param: dict) -> Parameter:
    # OpenAPI 3 nests the type under "schema"; Swagger 2 puts it on the parameter itself.
    # `param.get("schema") or param` handles both: use "schema" if there is one, else the parameter.
    schema = param.get("schema") or param
    location = param["in"]
    return Parameter(
        name=param["name"],
        location=location,
        # Use the spec's "required" value (False if it doesn't say). A path parameter is always
        # required, because the URL can't be built without it.
        required=bool(param.get("required", False)) or location == "path",
        type=_type_label(schema),
    )


def _request_fields(operation: dict, parameters: list[dict]) -> list[RequestField]:
    # OpenAPI 3: requestBody.content.<media type>.schema
    content = (operation.get("requestBody") or {}).get("content") or {}
    if content:
        # Prefer the JSON version of the body; otherwise take the first media type listed.
        media = content.get("application/json") or next(iter(content.values()))
        return _schema_fields((media or {}).get("schema") or {})

    # Swagger 2: an "in: body" parameter carries a schema; "in: formData" parameters are the fields.
    for param in parameters:
        if param.get("in") == "body":
            return _schema_fields(param.get("schema") or {})
    return [
        RequestField(name=p["name"], required=bool(p.get("required", False)), type=_type_label(p))
        for p in parameters
        if p.get("in") == "formData"
    ]  # empty list when the operation has no body at all (a GET, usually)


def _schema_fields(schema: dict) -> list[RequestField]:
    # Turn an object schema into one RequestField per top-level property.
    properties, required = _collect_properties(schema)
    return [
        RequestField(name=name, required=name in required, type=_type_label(sub))
        for name, sub in properties.items()
    ]


def _collect_properties(schema: dict) -> tuple[dict[str, dict], set[str]]:
    """Gather the properties of an object schema, merging allOf branches."""
    properties: dict[str, dict] = {}
    required: set[str] = set(schema.get("required") or [])  # a set, so duplicates collapse
    # "allOf" builds a schema out of several pieces that all apply at once (e.g. base fields +
    # extras). This function calls itself on each piece and merges the results.
    for branch in schema.get("allOf") or []:
        sub_properties, sub_required = _collect_properties(branch or {})
        properties.update(sub_properties)
        required |= sub_required  # `|=` adds the piece's required names to ours (set union)
    # The schema's own properties go last, so they win over same-named ones from allOf.
    properties.update(schema.get("properties") or {})
    return properties, required


def _type_label(schema: dict) -> str | None:
    # Produce a short, human-readable type like "integer", "array[string]" or "object".
    schema_type = schema.get("type")
    if schema_type == "array":
        # Look inside "items" to say what the array holds.
        item_type = _type_label(schema.get("items") or {})
        return f"array[{item_type}]" if item_type else "array"
    # Specs often leave out "type": "object" when the schema clearly has fields.
    if schema_type is None and ("properties" in schema or "allOf" in schema):
        return "object"
    # OpenAPI 3.1 allows a list like ["string", "null"]. "null" only means "may be empty", so
    # drop it; several real types left are joined, e.g. "string|integer".
    if isinstance(schema_type, list):
        real = [str(t) for t in schema_type if t != "null"]
        return "|".join(real) or None
    return schema_type if isinstance(schema_type, str) else None


def _requires_auth(operation: dict, spec: dict) -> bool:
    # An operation's own "security" replaces the global one, and "security: []" switches auth off.
    # .get(key, default) only uses the default when the key is ABSENT, so an explicit [] is kept.
    security = operation.get("security", spec.get("security"))
    if not security:  # None (never mentioned) or [] (explicitly no auth)
        return False
    # "security" is a list of alternatives; meeting any one of them is enough.
    # An empty requirement object ({}) is an alternative that means "no credentials needed".
    return all(bool(requirement) for requirement in security)
