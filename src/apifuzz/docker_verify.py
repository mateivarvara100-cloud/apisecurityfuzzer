"""Confirm that a scan target is a running local Docker container (the --require-docker mode).

Why: a lab target in Docker is the safest thing to point a scanner at. With --require-docker, a
typo in --base-url (or a .env left over from a real environment) can't send scan traffic anywhere
except a container running on this machine.

How: ask the Docker CLI for the running containers (`docker ps` + `docker inspect`) and check that
the target's host:port is one they publish. Two kinds of address count:

* a loopback address written literally (localhost, 127.0.0.1, ::1) on a port a container
  publishes on all interfaces or on loopback; or
* a container's own network IP on a port that container exposes (works on Linux bridge networks).

Hostnames are never resolved through DNS. Only those literal names count, so a name that happens
to resolve to 127.0.0.1 can't slip past the check.
"""

import json
import subprocess
from collections.abc import Callable
from urllib.parse import urlsplit

from pydantic import BaseModel

from apifuzz.errors import DockerVerifyError
from apifuzz.http_client import DEFAULT_PORTS

# Hosts that mean "this machine", accepted only as written (lower case, brackets removed).
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
# A port published on one of these host IPs is reachable through loopback.
_REACHABLE_VIA_LOOPBACK = {"", "0.0.0.0", "::", "127.0.0.1", "::1"}

# Runs a docker command and returns its stdout. Tests pass a fake one instead.
Runner = Callable[[list[str]], str]


class Container(BaseModel):
    """The parts of a running container that matter for matching a target."""

    id: str
    name: str  # without docker's leading "/"
    image: str
    # Published ports: (host_ip, host_port, container_port) e.g. ("0.0.0.0", 8000, "8000/tcp").
    published: list[tuple[str, int, str]] = []
    ips: list[str] = []  # the container's own addresses on its networks
    exposed: list[int] = []  # TCP ports the container exposes (reachable on its own IPs)


class DockerMatch(BaseModel):
    """A target address and the container that serves it."""

    host: str
    port: int
    container: Container
    how: str  # a human-readable explanation, e.g. "publishes 8000/tcp on 0.0.0.0:8000"

    @property
    def entry(self) -> str:
        """The exact allowlist entry for this match, e.g. "localhost:8000" or "[::1]:8000"."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def _run_docker(args: list[str]) -> str:
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        raise DockerVerifyError(
            "can't verify the target: the docker command was not found. Install Docker "
            "(or, for a scan, drop --require-docker)."
        ) from None
    except subprocess.TimeoutExpired:
        raise DockerVerifyError("docker did not answer within 20 seconds; is the Docker daemon running?") from None
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()
        raise DockerVerifyError(f"docker {args[0]} failed: {detail[0] if detail else 'no output'}")
    return done.stdout


def running_containers(run: Runner = _run_docker) -> list[Container]:
    """Every running container, read from `docker ps` and `docker inspect`."""
    ids = run(["ps", "-q", "--no-trunc"]).split()
    if not ids:
        return []
    try:
        details = json.loads(run(["inspect", *ids]))
    except json.JSONDecodeError as exc:
        raise DockerVerifyError(f"could not read docker inspect output: {exc}") from exc
    return [_to_container(d) for d in details if (d.get("State") or {}).get("Running")]


def _to_container(d: dict) -> Container:
    net = d.get("NetworkSettings") or {}
    published = []
    for container_port, bindings in (net.get("Ports") or {}).items():
        if not container_port.endswith("/tcp"):
            continue  # HTTP runs over TCP; UDP ports can't be a scan target
        for b in bindings or []:  # None when the port is exposed but not published
            try:
                published.append((b.get("HostIp") or "", int(b["HostPort"]), container_port))
            except (KeyError, TypeError, ValueError):
                continue  # a binding without a usable port number
    exposed = []
    for port in ((d.get("Config") or {}).get("ExposedPorts") or {}):
        number, _, proto = port.partition("/")
        if proto in ("", "tcp") and number.isdigit():
            exposed.append(int(number))
    ips = [n["IPAddress"] for n in (net.get("Networks") or {}).values() if n and n.get("IPAddress")]
    return Container(
        id=str(d.get("Id", ""))[:12],
        name=str(d.get("Name", "")).lstrip("/"),
        image=str((d.get("Config") or {}).get("Image", "")),
        published=published,
        ips=ips,
        exposed=exposed,
    )


def _host_port(target: str) -> tuple[str, int]:
    """Split a URL or "host:port" entry into (host, port), using 80/443 for a URL with no port."""
    parsed = urlsplit(target if "://" in target else f"//{target}")
    try:
        host, port = parsed.hostname, parsed.port
    except ValueError:
        host, port = None, None
    if not host:
        raise DockerVerifyError(f"{target!r} has no usable host")
    if port is None:
        if parsed.scheme not in DEFAULT_PORTS:
            raise DockerVerifyError(
                f"allowlist entry {target!r} has no port; with --require-docker every entry must be host:port"
            )
        port = DEFAULT_PORTS[parsed.scheme]
    return host, port


def match_target(target: str, containers: list[Container]) -> DockerMatch:
    """Return the container serving `target` (a URL or host:port), or raise DockerVerifyError."""
    host, port = _host_port(target)
    for c in containers:
        for host_ip, host_port, container_port in c.published:
            if host_port != port:
                continue
            if (host in _LOOPBACK and host_ip in _REACHABLE_VIA_LOOPBACK) or host == host_ip:
                return DockerMatch(
                    host=host, port=port, container=c,
                    how=f"publishes {container_port} on {host_ip or '0.0.0.0'}:{host_port}",
                )
        if host in c.ips and port in c.exposed:
            return DockerMatch(host=host, port=port, container=c, how=f"has IP {host} and exposes {port}/tcp")

    if not containers:
        raise DockerVerifyError(f"{target}: no Docker containers are running")
    if host not in _LOOPBACK and not any(host in c.ips for c in containers):
        raise DockerVerifyError(
            f"{target}: host {host!r} is not localhost, 127.0.0.1, ::1 or a running container's IP"
        )
    raise DockerVerifyError(f"{target}: no running container publishes port {port}")


def verify_targets(base_url: str, extra_entries: list[str], run: Runner = _run_docker) -> list[DockerMatch]:
    """Check the base URL and every extra allowlist entry. All must match a running container.

    Returns one match per target (base URL first), so the caller can build an allowlist of
    exact host:port entries and show which container each one belongs to.
    """
    containers = running_containers(run)
    return [match_target(t, containers) for t in [base_url, *extra_entries]]
