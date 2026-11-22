"""The network guard for users' own APIs: only public addresses, checked on every connection."""

import socket

import httpcore
import httpx
import pytest

from apifuzz_web import netguard
from apifuzz_web.netguard import (
    BlockedAddress,
    GuardedTransport,
    capped,
    check_user_url,
    proxy_configured,
    public_addresses,
)


def resolver(*answers: str | list[str]):
    """A stand-in for socket.getaddrinfo: each call returns the next answer (the last one repeats)."""
    calls: list[str] = []

    def resolve(host: str, port: int, **_: object) -> list[tuple]:
        calls.append(host)
        answer = answers[min(len(calls), len(answers)) - 1]
        addresses = answer if isinstance(answer, list) else [answer]
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in addresses]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


# ---- the address a user enters -----------------------------------------------------------------

@pytest.mark.parametrize("url, origin", [
    ("https://api.example.com", "https://api.example.com"),
    ("https://API.Example.com/v1/", "https://api.example.com"),
    ("https://api.example.com:443", "https://api.example.com"),
    ("https://api.example.com:8443/x", "https://api.example.com:8443"),
])
def test_an_https_address_is_accepted(url, origin):
    assert check_user_url(url) == origin


@pytest.mark.parametrize("url, says", [
    ("http://api.example.com", "https"),
    ("ftp://api.example.com", "https"),
    ("https://api.example.com:22", "443 or 8443"),
    ("https://api.example.com:8080", "443 or 8443"),
    ("https://user:pw@api.example.com", "user name"),
    ("https://", "full address"),
    ("https://api.example.com:notaport", "isn't a number"),
])
def test_other_addresses_are_refused_with_a_reason(url, says):
    with pytest.raises(ValueError, match=says):
        check_user_url(url)


# ---- which addresses count as public -------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "10.0.0.5", "172.16.0.1", "192.168.1.1",  # private
    "127.0.0.1", "::1",                      # this machine
    "169.254.169.254",                       # cloud metadata (link-local)
    "fe80::1",                               # IPv6 link-local
    "100.64.0.1",                            # shared carrier space
    "0.0.0.0",                               # "this network"
    "fc00::1",                               # IPv6 private
    "::ffff:10.0.0.1",                       # IPv4 private written as IPv6
    "224.0.0.1",                             # multicast
    "192.0.2.10",                            # documentation range
])
def test_internal_addresses_are_refused(address):
    with pytest.raises(BlockedAddress, match="not a public internet address"):
        public_addresses("api.example.com", 443, resolver(address))


def test_public_addresses_are_allowed():
    assert public_addresses("api.example.com", 443, resolver(["93.184.216.34", "2606:2800:220:1::1"])) == [
        "93.184.216.34", "2606:2800:220:1::1"]


def test_one_internal_address_among_public_ones_is_refused():
    with pytest.raises(BlockedAddress, match="10.0.0.5"):
        public_addresses("api.example.com", 443, resolver(["93.184.216.34", "10.0.0.5"]))


def test_a_name_that_does_not_resolve_is_refused():
    def fails(*_: object, **__: object) -> list:
        raise socket.gaierror("no such name")

    with pytest.raises(BlockedAddress, match="doesn't resolve"):
        public_addresses("nope.invalid", 443, fails)


# ---- every connection is checked, and goes to the address that was checked ---------------------

@pytest.fixture
def connections(monkeypatch):
    """Record where the guarded layer really connects, without opening a socket."""
    made: list[tuple[str, int]] = []

    def connect(self, host, port, timeout=None, local_address=None, socket_options=None):
        made.append((host, port))
        raise httpcore.ConnectError("stopped by the test")

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    return made


def test_a_connection_goes_to_the_checked_address_not_the_name(connections):
    backend = netguard._GuardedBackend(resolver("93.184.216.34"))
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("api.example.com", 443)
    assert connections == [("93.184.216.34", 443)]  # pinned: the name is never resolved again


def test_a_name_that_turns_internal_later_is_refused_on_the_next_connection(connections):
    # DNS rebinding: public when first checked, internal a moment later.
    resolve = resolver("93.184.216.34", "10.0.0.5")
    backend = netguard._GuardedBackend(resolve)
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("api.example.com", 443)
    with pytest.raises(BlockedAddress, match="10.0.0.5"):
        backend.connect_tcp("api.example.com", 443)
    assert connections == [("93.184.216.34", 443)]  # nothing was opened to the internal address


def test_local_sockets_are_refused():
    with pytest.raises(BlockedAddress):
        netguard._GuardedBackend(resolver("93.184.216.34")).connect_unix_socket("/var/run/docker.sock")


def test_the_transport_really_refuses_a_private_address():
    # The whole stack, as the engine uses it: httpx -> GuardedTransport -> the guarded layer.
    # If an httpx update stopped using the replaced pool, this request would go out instead.
    with httpx.Client(transport=GuardedTransport(resolver("127.0.0.1"))) as client:
        with pytest.raises(httpx.ConnectError, match="not a public internet address"):
            client.get("https://api.example.com/openapi.json")


def test_the_transport_refuses_the_real_localhost():
    with httpx.Client(transport=GuardedTransport()) as client, pytest.raises(httpx.ConnectError):
        client.get("https://localhost:8443/")


# ---- answers are size-capped -----------------------------------------------------------------------

def test_a_large_answer_is_cut_off():
    big = httpx.Response(200, stream=httpx.ByteStream(b"x" * 2_000_001))
    with pytest.raises(httpx.ReadError, match="larger than 2 MB"):
        capped(big, 2_000_000).read()


def test_an_answer_within_the_cap_is_unchanged():
    small = httpx.Response(200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(b'{"a": 1}'))
    out = capped(small, 1000)
    assert out.read() == b'{"a": 1}' and out.headers["content-type"] == "application/json"


# ---- a proxy would route around all of this ---------------------------------------------------

def test_a_proxy_in_the_environment_is_noticed():
    assert proxy_configured({"HTTPS_PROXY": "http://proxy:3128"})
    assert proxy_configured({"all_proxy": "socks5://proxy"})
    assert not proxy_configured({"PATH": "/usr/bin"})
