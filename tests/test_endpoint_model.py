# Tests for endpoint_model.build_endpoints: turning a spec into a list of Endpoint objects.

import pytest

from apifuzz.endpoint_model import build_endpoints
from apifuzz.spec_loader import load_spec
from conftest import minimal_spec


# Loads the sample spec once per test and indexes its endpoints by (method, path).
@pytest.fixture
def sample_endpoints(sample_spec_path):
    return {(e.method, e.path): e for e in build_endpoints(load_spec(str(sample_spec_path)))}


# The sample spec produces exactly these six endpoints, no more and no fewer.
def test_sample_lists_exactly_the_expected_endpoints(sample_endpoints):
    assert set(sample_endpoints) == {
        ("POST", "/login"),
        ("GET", "/me"),
        ("POST", "/orders"),
        ("GET", "/orders/{id}"),
        ("PATCH", "/users/{id}"),
        ("GET", "/search"),
    }


# Login-required is read from the global security setting and from each operation's override.
def test_auth_follows_global_default_and_operation_overrides(sample_endpoints):
    assert sample_endpoints[("GET", "/me")].requires_auth is True  # global bearerAuth
    assert sample_endpoints[("POST", "/login")].requires_auth is False  # security: []
    assert sample_endpoints[("GET", "/search")].requires_auth is False  # [{}, {bearerAuth}] allows anonymous


# A parameter declared on the path (not the method) still shows up on the method's endpoint.
def test_path_level_parameter_applies_to_the_operation(sample_endpoints):
    params = sample_endpoints[("GET", "/orders/{id}")].parameters

    assert [(p.name, p.location, p.required, p.type) for p in params] == [("id", "path", True, "integer")]


# A query parameter declared on the operation is listed with its name, location and type.
def test_operation_parameter_is_listed(sample_endpoints):
    params = sample_endpoints[("GET", "/search")].parameters

    assert [(p.name, p.location, p.required, p.type) for p in params] == [("q", "query", True, "string")]


# Body fields come from the request body schema, with the right required flags; GET has none.
def test_request_fields_come_from_the_body_schema(sample_endpoints):
    login = sample_endpoints[("POST", "/login")].request_fields
    patch = sample_endpoints[("PATCH", "/users/{id}")].request_fields

    assert [(f.name, f.required, f.type) for f in login] == [("username", True, "string"), ("password", True, "string")]
    assert [(f.name, f.required) for f in patch] == [("name", False), ("email", False)]
    assert sample_endpoints[("GET", "/me")].request_fields == []


# operationId and summary are copied from the spec onto the endpoint.
def test_metadata_is_carried_over(sample_endpoints):
    login = sample_endpoints[("POST", "/login")]

    assert login.operation_id == "login"
    assert login.summary == "Log in and receive a token"


# When the path and the operation both declare the same parameter, the operation's version wins.
def test_operation_parameter_overrides_path_level_one():
    spec = minimal_spec(
        paths={
            "/things": {
                "parameters": [{"name": "limit", "in": "query", "schema": {"type": "string"}}],
                "get": {"parameters": [{"name": "limit", "in": "query", "required": True, "schema": {"type": "integer"}}]},
            }
        }
    )

    (endpoint,) = build_endpoints(spec)

    assert [(p.type, p.required) for p in endpoint.parameters] == [("integer", True)]


# Keys in a path item that aren't HTTP methods ("summary", "x-internal") don't become endpoints.
def test_non_operation_keys_in_a_path_item_are_ignored():
    spec = minimal_spec(paths={"/things": {"summary": "shared", "x-internal": True, "get": {}}})

    assert [(e.method, e.path) for e in build_endpoints(spec)] == [("GET", "/things")]


# A body schema built from several allOf pieces lists the fields of all the pieces combined.
def test_allof_body_schemas_are_merged():
    body = {
        "content": {
            "application/json": {
                "schema": {
                    "allOf": [
                        {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}},
                        {"type": "object", "properties": {"b": {"type": "array", "items": {"type": "integer"}}}},
                    ]
                }
            }
        }
    }
    spec = minimal_spec(paths={"/x": {"post": {"requestBody": body}}})

    (endpoint,) = build_endpoints(spec)

    assert [(f.name, f.required, f.type) for f in endpoint.request_fields] == [
        ("a", True, "string"),
        ("b", False, "array[integer]"),
    ]


# Swagger 2 specs: "in: body" and "in: formData" become body fields, not parameters,
# and the global/operation security rules work the same as in OpenAPI 3.
def test_swagger_2_body_and_form_parameters():
    spec = {
        "swagger": "2.0",
        "info": {"title": "old", "version": "1"},
        "security": [{"api_key": []}],
        "paths": {
            "/pets": {
                "post": {
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}},
                        },
                        {"name": "dry_run", "in": "query", "type": "boolean"},
                    ]
                }
            },
            "/upload": {
                "post": {
                    "security": [],
                    "parameters": [{"name": "file", "in": "formData", "required": True, "type": "file"}],
                }
            },
        },
    }

    endpoints = {e.path: e for e in build_endpoints(spec)}

    pets = endpoints["/pets"]
    assert [(f.name, f.required) for f in pets.request_fields] == [("name", True)]
    assert [(p.name, p.location, p.type) for p in pets.parameters] == [("dry_run", "query", "boolean")]
    assert pets.requires_auth is True
    upload = endpoints["/upload"]
    assert [(f.name, f.required, f.type) for f in upload.request_fields] == [("file", True, "file")]
    assert upload.parameters == []
    assert upload.requires_auth is False
