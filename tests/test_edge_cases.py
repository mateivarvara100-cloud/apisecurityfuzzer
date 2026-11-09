# Edge cases for the spec loader, the endpoint model and the HTTP client that the main test
# files don't cover.

import httpx
import pytest

from apifuzz.endpoint_model import build_endpoints
from apifuzz.errors import AllowlistError, RequestError, SpecError
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.spec_loader import load_spec
from conftest import minimal_spec


# Helper: an httpx client whose "network" is the given function, so no real requests are made.
def _mock(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# Helper: an HttpClient that allows localhost:8000 and whose "network" is the given function.
def _client(handler) -> HttpClient:
    return HttpClient(Allowlist(["localhost:8000"]), transport=httpx.MockTransport(handler))


class TestSpecLoader:
    # Pointing at a folder says so, instead of Windows' misleading "Permission denied".
    def test_folder_is_rejected_clearly(self, tmp_path):
        with pytest.raises(SpecError, match="is a folder"):
            load_spec(str(tmp_path))

    # A file that isn't UTF-8 text is rejected with "could not read file".
    def test_non_utf8_file_is_rejected(self, tmp_path):
        path = tmp_path / "spec.json"
        path.write_bytes(b"\xff\xfe\x00garbage")

        with pytest.raises(SpecError, match="could not read file"):
            load_spec(str(path))

    # Only http(s) URLs are fetched; other schemes get a clear message and nothing is downloaded.
    def test_unsupported_url_scheme_is_rejected(self):
        def handler(request):
            raise AssertionError("must not fetch")

        with pytest.raises(SpecError, match="unsupported URL scheme 'ftp'"):
            load_spec("ftp://example.com/openapi.json", client=_mock(handler))

    # A URL scheme in capitals is still recognised as http(s).
    def test_uppercase_http_scheme_is_fetched(self, sample_spec_path):
        body = sample_spec_path.read_text(encoding="utf-8")

        spec = load_spec("HTTP://localhost:8000/openapi.json", client=_mock(lambda r: httpx.Response(200, text=body)))

        assert spec["info"]["title"] == "VulnShop (sample)"

    # A server error (500) while fetching names the status code.
    def test_url_server_error_is_a_spec_error(self):
        with pytest.raises(SpecError, match="HTTP 500"):
            load_spec("http://localhost:8000/openapi.json", client=_mock(lambda r: httpx.Response(500)))

    # A URL that answers 200 with a login page instead of a spec is rejected like a bad file.
    def test_url_returning_html_is_rejected(self):
        page = "<html><body>Login required</body></html>"

        with pytest.raises(SpecError):
            load_spec("http://localhost:8000/openapi.json", client=_mock(lambda r: httpx.Response(200, text=page)))

    # Valid YAML that isn't a spec (a plain list) is rejected.
    def test_yaml_that_is_not_a_spec_is_rejected(self, write_spec):
        with pytest.raises(SpecError):
            load_spec(write_spec("- just\n- a list\n", "spec.yaml"))

    # A file that starts with a UTF-8 byte-order mark (common from Windows editors) still loads.
    def test_utf8_bom_file_loads(self, tmp_path, sample_spec_path):
        path = tmp_path / "bom.json"
        path.write_bytes(b"\xef\xbb\xbf" + sample_spec_path.read_bytes())

        assert load_spec(str(path))["info"]["title"] == "VulnShop (sample)"


class TestEndpointModel:
    # OpenAPI 3.1 type lists: "null" is dropped, and several real types are joined with "|".
    def test_openapi_31_type_lists(self):
        params = [
            {"name": "a", "in": "query", "schema": {"type": ["string", "null"]}},
            {"name": "b", "in": "query", "schema": {"type": ["string", "integer"]}},
            {"name": "c", "in": "query", "schema": {"type": ["null"]}},
        ]
        spec = minimal_spec(openapi="3.1.0", paths={"/x": {"get": {"parameters": params}}})

        (endpoint,) = build_endpoints(spec)

        assert [p.type for p in endpoint.parameters] == ["string", "string|integer", None]

    # A body with no JSON media type uses the first one listed (a form here).
    def test_non_json_body_uses_the_first_media_type(self):
        body = {"content": {"application/x-www-form-urlencoded": {"schema": {"properties": {"f": {"type": "string"}}}}}}
        spec = minimal_spec(paths={"/form": {"post": {"requestBody": body}}})

        (endpoint,) = build_endpoints(spec)

        assert [(f.name, f.type) for f in endpoint.request_fields] == [("f", "string")]

    # No security anywhere in the spec means no login is needed.
    def test_no_security_anywhere_means_no_auth(self):
        (endpoint,) = build_endpoints(minimal_spec(paths={"/x": {"get": {}}}))

        assert endpoint.requires_auth is False

    # An operation can require auth on its own even when the spec has no global security.
    def test_operation_security_without_global_security(self):
        (endpoint,) = build_endpoints(minimal_spec(paths={"/x": {"get": {"security": [{"key": []}]}}}))

        assert endpoint.requires_auth is True

    # Tags and the deprecated flag are copied over; they default to none / False.
    def test_tags_and_deprecated_are_carried_over(self):
        spec = minimal_spec(paths={"/old": {"get": {"tags": ["legacy"], "deprecated": True}, "post": {}}})

        get, post = build_endpoints(spec)

        assert (get.tags, get.deprecated) == (["legacy"], True)
        assert (post.tags, post.deprecated) == ([], False)

    # A path item that isn't a mapping is skipped instead of crashing.
    def test_malformed_path_item_is_skipped(self):
        spec = minimal_spec(paths={"/bad": None, "/good": {"get": {}}})

        assert [e.path for e in build_endpoints(spec)] == ["/good"]

    # A path parameter is always required, even if the spec forgets to say so.
    def test_path_parameter_is_always_required(self):
        spec = minimal_spec(paths={"/x/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}}})

        (endpoint,) = build_endpoints(spec)

        assert endpoint.parameters[0].required is True


class TestHttpClient:
    # params are added to a query string already in the URL, and the combined URL is recorded.
    def test_params_merge_with_existing_query_string(self):
        exchange = _client(lambda r: httpx.Response(200)).request(
            "GET", "http://localhost:8000/search?q=a", params={"page": "2"}
        )

        assert exchange.request.url == "http://localhost:8000/search?q=a&page=2"

    # A response body that isn't valid UTF-8 is still recorded (bad bytes replaced), not a crash.
    def test_binary_response_body_is_decoded_safely(self):
        exchange = _client(lambda r: httpx.Response(200, content=b"ok\xff\xfe")).request(
            "GET", "http://localhost:8000/bin"
        )

        assert exchange.response.body.startswith("ok")
        assert "�" in exchange.response.body

    # A timeout becomes a RequestError that names the method and URL.
    def test_timeout_becomes_request_error(self):
        def handler(request):
            raise httpx.ReadTimeout("timed out", request=request)

        with pytest.raises(RequestError, match="GET http://localhost:8000/slow"):
            _client(handler).request("get", "http://localhost:8000/slow")

    # The check uses the URL's real host: an allowed host inside a query value doesn't help.
    def test_allowlisted_host_in_query_does_not_help(self):
        sent = []
        client = _client(lambda r: sent.append(r) or httpx.Response(200))

        with pytest.raises(AllowlistError):
            client.request("GET", "http://evil.test/", params={"next": "http://localhost:8000/"})
        assert sent == []

    # Entries with surrounding whitespace (e.g. read from a config file) still work.
    def test_allowlist_entries_are_trimmed(self):
        assert Allowlist(["  localhost:8000 \n"]).permits("http://localhost:8000/x")

    # An IPv6 entry without a port allows that address on any port.
    def test_ipv6_entry_without_port(self):
        allowlist = Allowlist(["[::1]"])

        assert allowlist.permits("http://[::1]:9000/x")
        assert not allowlist.permits("http://[::2]:9000/x")
