# Tests for spec_loader.load_spec: reading specs from files and URLs, and rejecting bad ones.

import json

import httpx
import pytest

from apifuzz.errors import SpecError
from apifuzz.spec_loader import load_spec
from conftest import minimal_spec


# The sample spec loads, and every $ref in it is replaced by the real content.
def test_loads_sample_and_inlines_refs(sample_spec_path):
    spec = load_spec(str(sample_spec_path))

    assert spec["info"]["title"] == "VulnShop (sample)"
    assert "$ref" not in json.dumps(spec)
    login_schema = spec["paths"]["/login"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert set(login_schema["properties"]) == {"username", "password"}


# A path to a file that doesn't exist gives a SpecError saying "file not found".
def test_missing_file_is_a_spec_error():
    with pytest.raises(SpecError, match="file not found"):
        load_spec("does-not-exist.json")


# A file containing only whitespace is rejected as empty.
def test_empty_file_is_rejected(write_spec):
    with pytest.raises(SpecError, match="empty"):
        load_spec(write_spec("  \n"))


# Text that isn't JSON or YAML is rejected.
def test_garbage_is_rejected(write_spec):
    with pytest.raises(SpecError):
        load_spec(write_spec("this is {{ not a spec"))


# A spec that breaks the OpenAPI rules is rejected, and the message says what and where.
def test_invalid_spec_names_the_problem_and_where(write_spec):
    spec = minimal_spec(info={"title": "t"})  # info.version is required

    with pytest.raises(SpecError) as caught:
        load_spec(write_spec(spec))

    assert "version" in str(caught.value)
    assert "info" in str(caught.value)


# A $ref pointing at nothing is rejected, and prance's fake filename is kept out of the message.
def test_unresolvable_ref_is_rejected_without_prance_internals(write_spec):
    spec = minimal_spec(
        paths={
            "/a": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Nope"}}},
                        }
                    }
                }
            }
        }
    )

    with pytest.raises(SpecError) as caught:
        load_spec(write_spec(spec))

    assert "Nope" in str(caught.value)
    assert "placeholder" not in str(caught.value)


# A schema that refers to itself (a category with a parent category) loads instead of failing.
def test_recursive_schema_loads(write_spec):
    spec = minimal_spec(
        paths={
            "/categories": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Category"}}},
                        }
                    }
                }
            }
        },
        components={
            "schemas": {
                "Category": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "parent": {"$ref": "#/components/schemas/Category"}},
                }
            }
        },
    )

    assert "/categories" in load_spec(write_spec(spec))["paths"]


# A spec written in YAML loads as well as JSON.
def test_yaml_spec_loads(write_spec):
    yaml_spec = "openapi: 3.0.3\ninfo: {title: yaml api, version: '1'}\npaths: {}\n"

    assert load_spec(write_spec(yaml_spec, "spec.yaml"))["info"]["title"] == "yaml api"


# An older Swagger 2.0 spec loads.
def test_swagger_2_spec_loads(write_spec):
    swagger = {"swagger": "2.0", "info": {"title": "old", "version": "1"}, "paths": {}}

    assert load_spec(write_spec(swagger))["swagger"] == "2.0"


# Helper: an httpx client whose "network" is the given function, so no real requests are made.
def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# A spec can be downloaded from a URL, and exactly that URL is requested.
def test_loads_spec_from_url(sample_spec_path):
    body = sample_spec_path.read_text(encoding="utf-8")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text=body)

    spec = load_spec("http://localhost:8000/openapi.json", client=_client(handler))

    assert spec["info"]["title"] == "VulnShop (sample)"
    assert seen == ["http://localhost:8000/openapi.json"]


# A URL that answers with an error code (404) gives a SpecError naming the code.
def test_url_error_status_is_a_spec_error():
    with pytest.raises(SpecError, match="HTTP 404"):
        load_spec("http://localhost:8000/openapi.json", client=_client(lambda r: httpx.Response(404)))


# A URL that can't be reached at all gives a SpecError saying the fetch failed.
def test_unreachable_url_is_a_spec_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(SpecError, match="could not fetch"):
        load_spec("http://localhost:8000/openapi.json", client=_client(handler))
