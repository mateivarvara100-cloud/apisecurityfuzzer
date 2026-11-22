"""Keeps scans of user-supplied APIs on the public internet.

A user's API is checked twice. When it is added, check_user_url() gives a clear answer early. And
on every connection a scan of it opens, the connection layer below resolves the host itself,
refuses unless every address is public, and connects to the address it checked. That second
check is the one that counts: a hostname that pointed at a public address when it was added and
at an internal one a moment later (DNS rebinding) is still refused, because the address that is
checked is the address that is used. TLS still verifies the certificate for the hostname.

"Public" means what Python's ipaddress calls global: not private, loopback, link-local (which
includes the cloud metadata address 169.254.169.254), shared carrier space, multicast, reserved
or documentation ranges. An IPv4 address written as IPv6 (::ffff:10.0.0.1) is judged as IPv4.
"""

import ipaddress
import os
import socket
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

ALLOWED_PORTS = frozenset({443, 8443})
_PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")

Resolver = Callable[..., list[Any]]  # the shape of socket.getaddrinfo


class BlockedAddress(httpcore.ConnectError):
    """A connection refused before it was made, because of where it would go.

    A ConnectError underneath, so the engine reports it like a host that can't be reached.
    """


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop an IPv6 zone ("fe80::1%eth0")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def public_addresses(host: str, port: int, resolve: Resolver = socket.getaddrinfo) -> list[str]:
    """Every address `host` resolves to, if all of them are public. Otherwise BlockedAddress."""
    try:
        infos = resolve(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise BlockedAddress(f"{host} doesn't resolve to an address") from exc
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise BlockedAddress(f"{host} doesn't resolve to an address")
    for address in addresses:
        # One internal address among public ones is enough to refuse: the connection could use it.
        if not _is_public(address):
            raise BlockedAddress(f"{host} resolves to {address}, which is not a public internet address")
    return addresses


def proxy_configured(env: dict[str, str] | None = None) -> bool:
    """True if the server has a proxy set. httpx would send requests through it, around the guard."""
    values = os.environ if env is None else env
    return any(values.get(name) for name in _PROXY_VARIABLES)


def check_user_url(url: str) -> str:
    """The origin ("https://host[:port]") of a user's API address, or ValueError saying what's wrong."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise ValueError("Use an https:// address. Only APIs served over HTTPS can be scanned.")
    if not parts.hostname:
        raise ValueError("Enter a full address, like https://api.example.com.")
    if parts.username or parts.password:
        raise ValueError("Take the user name and password out of the address.")
    try:
        port = parts.port or 443
    except ValueError:
        raise ValueError("The port in the address isn't a number.") from None
    if port not in ALLOWED_PORTS:
        raise ValueError("Only the standard HTTPS ports can be scanned: 443 or 8443.")
    host = parts.hostname.lower()
    return f"https://{host}" if port == 443 else f"https://{host}:{port}"


class _GuardedBackend(httpcore.SyncBackend):
    def __init__(self, resolve: Resolver) -> None:
        self._resolve = resolve

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        last: Exception | None = None
        for address in public_addresses(host, port, self._resolve):
            try:
                return super().connect_tcp(address, port, timeout, local_address, socket_options)
            except httpcore.ConnectError as exc:
                last = exc
        raise last or BlockedAddress(f"couldn't connect to {host}")

    def connect_unix_socket(self, path: str, timeout: float | None = None,
                            socket_options: Iterable[Any] | None = None) -> httpcore.NetworkStream:
        raise BlockedAddress("connections to local sockets are not allowed")


class _Capped(httpx.SyncByteStream):
    """A response body that stops with an error once it passes `limit` bytes."""

    def __init__(self, stream: httpx.SyncByteStream, limit: int) -> None:
        self._stream, self._limit = stream, limit

    def __iter__(self) -> Any:
        received = 0
        for chunk in self._stream:
            received += len(chunk)
            if received > self._limit:
                raise httpx.ReadError(f"the answer was larger than {self._limit // 1_000_000} MB, so it was cut off")
            yield chunk

    def close(self) -> None:
        self._stream.close()


def capped(response: httpx.Response, limit: int) -> httpx.Response:
    """The same response, with its body limited to `limit` bytes."""
    assert isinstance(response.stream, httpx.SyncByteStream)
    return httpx.Response(response.status_code, headers=response.headers, stream=_Capped(response.stream, limit),
                          extensions=response.extensions)


class GuardedTransport(httpx.HTTPTransport):
    """httpx's own transport, connecting only through the public-address check above.

    It verifies TLS certificates, uses no proxy, never sees a redirect it would follow (the engine
    follows none), and cuts off any answer larger than `max_response_bytes`, so a hostile API can't
    fill the server's memory. It replaces the connection pool httpx built with one that uses the
    guarded connection layer; a test checks that a private address is really refused, so a change
    in httpx that bypassed this would show up there.
    """

    def __init__(self, resolve: Resolver = socket.getaddrinfo, max_response_bytes: int = 5_000_000) -> None:
        super().__init__(verify=True, trust_env=False)
        self._max_response_bytes = max_response_bytes
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            network_backend=_GuardedBackend(resolve),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return capped(super().handle_request(request), self._max_response_bytes)
