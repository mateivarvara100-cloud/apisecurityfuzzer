# Tests for docker_verify: deciding whether a target belongs to a running local container.
# No real Docker is needed; containers are built directly, and the CLI runner is a stub.

import pytest
from typer.testing import CliRunner

from apifuzz.cli import app
from apifuzz.docker_verify import Container, match_target, running_containers, verify_targets
from apifuzz.errors import DockerVerifyError
from apifuzz.settings import resolve_settings

runner = CliRunner()

WEB = Container(
    id="111", name="web", image="lab-api:1",
    published=[("0.0.0.0", 8000, "8000/tcp")], ips=["172.17.0.2"], exposed=[8000],
)
LOOPBACK_ONLY = Container(
    id="222", name="admin", image="lab-admin:1",
    published=[("127.0.0.1", 9000, "80/tcp")], ips=["172.17.0.3"], exposed=[80],
)
LAN_ONLY = Container(id="333", name="lan", image="lab-lan:1", published=[("192.168.1.5", 7000, "80/tcp")])
LAB = [WEB, LOOPBACK_ONLY, LAN_ONLY]


class TestMatchTarget:
    # Each literal loopback spelling reaches a port published on all interfaces.
    @pytest.mark.parametrize("url", ["http://localhost:8000", "http://127.0.0.1:8000/api", "http://[::1]:8000"])
    def test_loopback_names(self, url):
        assert match_target(url, LAB).container.name == "web"

    # A port bound only to 127.0.0.1 is reachable via loopback.
    def test_loopback_bound_port(self):
        assert match_target("http://localhost:9000", LAB).container.name == "admin"

    # A port bound to a specific LAN address matches only that address, not localhost.
    def test_specific_host_ip(self):
        assert match_target("http://192.168.1.5:7000", LAB).container.name == "lan"
        with pytest.raises(DockerVerifyError, match="no running container publishes port 7000"):
            match_target("http://localhost:7000", LAB)

    # A container's own IP works on a port it exposes.
    def test_container_ip(self):
        assert match_target("http://172.17.0.3:80", LAB).container.name == "admin"

    # A URL with no port uses the scheme default (80 here), which nothing publishes on loopback.
    def test_default_port(self):
        with pytest.raises(DockerVerifyError, match="port 80"):
            match_target("http://localhost/", LAB)

    # Hostnames other than "localhost" are refused, even if they would resolve to 127.0.0.1.
    def test_other_hostnames_refused(self):
        with pytest.raises(DockerVerifyError, match="is not localhost"):
            match_target("http://staging.example.com:8000", LAB)

    # No containers at all gives its own message.
    def test_no_containers(self):
        with pytest.raises(DockerVerifyError, match="no Docker containers are running"):
            match_target("http://localhost:8000", [])

    # An allowlist entry without a port is refused in this mode.
    def test_entry_without_port(self):
        with pytest.raises(DockerVerifyError, match="no port"):
            match_target("localhost", LAB)

    # The allowlist entry is exact host:port, with brackets for IPv6.
    def test_entry_format(self):
        assert match_target("http://localhost:8000", LAB).entry == "localhost:8000"
        assert match_target("http://[::1]:8000", LAB).entry == "[::1]:8000"


# Stub for the docker CLI: `ps` lists one id, `inspect` returns one container record.
def _stub(args):
    if args[0] == "ps":
        return "abc\n"
    return (
        '[{"Id": "abcdef0123456789", "Name": "/web", "State": {"Running": true},'
        ' "Config": {"Image": "lab-api:1", "ExposedPorts": {"8000/tcp": {}, "53/udp": {}}},'
        ' "NetworkSettings": {"Ports": {"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8000"}],'
        ' "53/udp": [{"HostIp": "0.0.0.0", "HostPort": "53"}], "9/tcp": null},'
        ' "Networks": {"bridge": {"IPAddress": "172.17.0.2"}}}}]'
    )


class TestDockerCli:
    # Inspect output is parsed: name without "/", short id, TCP bindings only.
    def test_parsing(self):
        (c,) = running_containers(_stub)

        assert (c.name, c.id, c.image) == ("web", "abcdef012345", "lab-api:1")
        assert c.published == [("0.0.0.0", 8000, "8000/tcp")]
        assert c.exposed == [8000] and c.ips == ["172.17.0.2"]

    # No running containers means `inspect` is never called.
    def test_empty_ps(self):
        calls = []

        def run(args):
            calls.append(args[0])
            return ""

        assert running_containers(run) == [] and calls == ["ps"]

    # verify_targets checks the base URL and each extra entry; one bad entry fails the lot.
    def test_verify_targets(self):
        assert [m.entry for m in verify_targets("http://localhost:8000", [], _stub)] == ["localhost:8000"]
        with pytest.raises(DockerVerifyError):
            verify_targets("http://localhost:8000", ["localhost:5000"], _stub)


class TestSettingsAndCli:
    # The env var turns the mode on; an explicit flag value wins over it.
    @pytest.mark.parametrize("value,expected", [("1", True), ("yes", True), ("", False), ("0", False)])
    def test_env_var(self, value, expected):
        assert resolve_settings(base_url="http://x", env={"APIFUZZ_REQUIRE_DOCKER": value}).require_docker is expected

    def test_flag_overrides_env(self):
        env = {"APIFUZZ_REQUIRE_DOCKER": "1"}
        assert resolve_settings(base_url="http://x", env=env, require_docker=False).require_docker is False

    # With --require-docker, a failed verification stops the scan before any request (exit 2).
    def test_scan_stops_when_unverified(self, sample_spec_path, monkeypatch):
        def refuse(*args, **kwargs):
            raise DockerVerifyError("no Docker containers are running")

        monkeypatch.setattr("apifuzz.cli.verify_targets", refuse)
        monkeypatch.setattr("apifuzz.cli.HttpClient", lambda *a, **k: pytest.fail("must not send requests"))

        result = runner.invoke(
            app,
            ["scan", str(sample_spec_path), "--i-have-authorization", "--base-url", "http://localhost:8000", "--require-docker"],
        )

        assert result.exit_code == 2
        assert "no Docker containers are running" in result.output

    # verify-docker prints the matched container.
    def test_verify_docker_command(self, monkeypatch):
        monkeypatch.setattr("apifuzz.cli.verify_targets", lambda t, e: [match_target(t, LAB)])

        result = runner.invoke(app, ["verify-docker", "http://localhost:8000"])

        assert result.exit_code == 0
        assert "web" in result.stdout and "lab-api:1" in result.stdout
