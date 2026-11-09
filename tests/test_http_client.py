# Tests for http_client: the host allowlist, and the HttpClient that sends and records requests.

import httpx
import pytest

from apifuzz.errors import AllowlistError, RequestError
from apifuzz.http_client import Allowlist, HttpClient


class TestAllowlist:
    # An entry without a port allows that host on any port.
    def test_host_entry_permits_any_port_on_that_host(self):
        allowlist = Allowlist(["staging.example.com"])

        assert allowlist.permits("https://staging.example.com/orders/1")
        assert allowlist.permits("http://staging.example.com:8080/orders/1")

    # An entry with a port allows only that port.
    def test_host_port_entry_permits_only_that_port(self):
        allowlist = Allowlist(["localhost:8000"])

        assert allowlist.permits("http://localhost:8000/x")
        assert not allowlist.permits("http://localhost:9000/x")
        assert not allowlist.permits("http://localhost/x")  # port 80

    # A URL with no port counts as 443 for https and 80 for http.
    def test_default_port_is_inferred_from_the_scheme(self):
        assert Allowlist(["example.com:443"]).permits("https://example.com/x")
        assert not Allowlist(["example.com:443"]).permits("http://example.com/x")

    # Other hosts, subdomains, and look-alike domains are refused.
    def test_unlisted_hosts_are_refused(self):
        allowlist = Allowlist(["staging.example.com"])

        assert not allowlist.permits("https://example.com/")
        assert not allowlist.permits("https://api.staging.example.com/")  # no implicit subdomains
        assert not allowlist.permits("https://staging.example.com.evil.test/")

    # "allowed-host@evil.test" really points at evil.test, so it is refused.
    def test_userinfo_trick_does_not_fool_the_check(self):
        allowlist = Allowlist(["staging.example.com"])

        assert not allowlist.permits("https://staging.example.com@evil.test/")

    # Upper/lower case in host names doesn't matter.
    def test_matching_ignores_case(self):
        assert Allowlist(["Staging.Example.com"]).permits("https://STAGING.example.COM/x")

    # Only http:// and https:// URLs are ever allowed.
    def test_only_http_and_https_are_permitted(self):
        allowlist = Allowlist(["localhost"])

        assert not allowlist.permits("ftp://localhost/x")
        assert not allowlist.permits("file:///etc/passwd")
        assert not allowlist.permits("localhost/x")

    # With no entries, nothing is allowed.
    def test_empty_allowlist_permits_nothing(self):
        assert not Allowlist().permits("http://localhost/")

    # Entries can be written as full URLs or as IPv6 addresses.
    def test_entries_may_be_written_as_urls_or_ipv6(self):
        assert Allowlist(["http://localhost:8000"]).permits("http://localhost:8000/x")
        assert Allowlist(["[::1]:8000"]).permits("http://[::1]:8000/x")

    # A URL with a bad port is refused, and an empty entry is a configuration error.
    def test_malformed_urls_and_entries(self):
        assert not Allowlist(["localhost"]).permits("http://localhost:notaport/")
        with pytest.raises(ValueError):
            Allowlist([""])

    # check() raises AllowlistError naming the refused host.
    def test_check_raises_for_refused_url(self):
        with pytest.raises(AllowlistError, match="evil.test"):
            Allowlist(["localhost"]).check("http://evil.test/")


# Helper: an HttpClient that allows localhost:8000 and whose "network" is the given function.
def _client(handler, allowed=("localhost:8000",), **kwargs) -> HttpClient:
    return HttpClient(Allowlist(allowed), transport=httpx.MockTransport(handler), **kwargs)


class TestHttpClient:
    # A request to a host not on the allowlist raises an error and never reaches the network.
    def test_refused_request_is_never_sent(self):
        sent = []
        client = _client(lambda request: sent.append(request) or httpx.Response(200))

        with pytest.raises(AllowlistError):
            client.request("GET", "http://evil.test/orders/1")
        with pytest.raises(AllowlistError):
            client.request("GET", "http://localhost:9999/orders/1")

        assert sent == []

    # The Exchange records the request exactly as sent and the response exactly as received.
    def test_records_the_raw_request_and_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(201, json={"id": 7}, headers={"X-Trace": "abc"})

        client = _client(handler)
        exchange = client.request(
            "post",
            "http://localhost:8000/orders",
            headers={"Authorization": "Bearer token-a"},
            params={"dry": "1"},
            json={"item": "book"},
        )

        assert exchange.request.method == "POST"
        assert exchange.request.url == "http://localhost:8000/orders?dry=1"
        assert exchange.request.headers["authorization"] == "Bearer token-a"
        assert exchange.request.body == '{"item":"book"}'
        assert exchange.response.status_code == 201
        assert exchange.response.headers["x-trace"] == "abc"
        assert exchange.response.body == '{"id":7}'
        assert exchange.response.truncated is False
        assert exchange.elapsed_ms >= 0

    # A request without a body is recorded with body None.
    def test_get_has_no_request_body(self):
        exchange = _client(lambda request: httpx.Response(200)).request("GET", "http://localhost:8000/me")

        assert exchange.request.body is None

    # A redirect is returned as-is and not followed, so it can't lead off the allowlist.
    def test_redirects_are_not_followed(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(302, headers={"Location": "http://evil.test/steal"})

        exchange = _client(handler).request("GET", "http://localhost:8000/old")

        assert exchange.response.status_code == 302
        assert exchange.response.headers["location"] == "http://evil.test/steal"
        assert calls == ["http://localhost:8000/old"]

    # A body over the size limit is cut to the limit and marked as truncated.
    def test_long_response_bodies_are_truncated(self):
        client = _client(lambda request: httpx.Response(200, text="x" * 1000), max_body_bytes=100)

        response = client.request("GET", "http://localhost:8000/big").response

        assert response.body == "x" * 100
        assert response.truncated is True

    # A body exactly at the limit is complete, so it isn't marked as truncated.
    def test_body_exactly_at_the_limit_is_not_marked_truncated(self):
        client = _client(lambda request: httpx.Response(200, text="x" * 100), max_body_bytes=100)

        assert client.request("GET", "http://localhost:8000/exact").response.truncated is False

    # A connection failure becomes our RequestError, carrying the original message.
    def test_network_failure_becomes_request_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        with pytest.raises(RequestError, match="connection refused"):
            _client(handler).request("GET", "http://localhost:8000/me")

    # The client works inside a `with` block.
    def test_works_as_a_context_manager(self):
        with _client(lambda request: httpx.Response(200)) as client:
            assert client.request("GET", "http://localhost:8000/me").response.status_code == 200
