# Engine features the hosted web app relies on: progress and a safe stop point in run_scan, and
# loading a spec that is already in hand (an uploaded file), with YAML aliases refused.

import json

import httpx
import pytest

from apifuzz.checks import Check, ScanContext
from apifuzz.checks.auth_required import AuthRequired
from apifuzz.endpoint_model import Endpoint
from apifuzz.errors import SpecError
from apifuzz.http_client import Allowlist, HttpClient
from apifuzz.scanner import run_scan
from apifuzz.settings import Settings
from apifuzz.spec_loader import load_spec, load_spec_text
from conftest import minimal_spec


def _ctx(handler) -> ScanContext:
    settings = Settings(base_url="http://localhost:8000", allowlist=["localhost:8000"])
    return ScanContext(HttpClient(Allowlist(settings.allowlist), transport=httpx.MockTransport(handler)), settings)


def _endpoints(n: int) -> list[Endpoint]:
    return [Endpoint(path=f"/e{i}", method="GET", requires_auth=True, parameters=[]) for i in range(n)]


def _unregistered(cls):
    """A check class with an id registers itself for every scan; keep test-only ones out."""
    Check._registry.remove(cls)
    return cls


@_unregistered
class Second(AuthRequired):
    id = "second"


class TestProgressAndStop:
    # on_step sees every (check, endpoint) step once, numbered from 0, with the total.
    def test_on_step_reports_every_step(self):
        steps: list[tuple[str, int, int]] = []

        run_scan(_endpoints(3), [AuthRequired, Second], _ctx(lambda r: httpx.Response(401)),
                 on_step=lambda check, i, total: steps.append((check, i, total)))

        assert steps == [("auth-required", 0, 6), ("auth-required", 1, 6), ("auth-required", 2, 6),
                         ("second", 3, 6), ("second", 4, 6), ("second", 5, 6)]

    # Asked to stop, the scan ends before the next step, keeps its findings and says why.
    def test_should_stop_ends_between_steps_and_keeps_findings(self):
        sent: list[str] = []

        def handler(request):
            sent.append(request.url.path)
            return httpx.Response(200)  # every endpoint is open: one finding each

        result = run_scan(_endpoints(4), [AuthRequired], _ctx(handler),
                          should_stop=lambda: "cancelled" if len(set(sent)) >= 2 else None)

        assert sorted(set(sent)) == ["/e0", "/e1"]
        assert [f.endpoint for f in result.findings] == ["GET /e0", "GET /e1"]
        assert result.incomplete is True
        assert "scan stopped early: cancelled" in result.errors
        # Only the steps that ran are counted as tested.
        assert result.coverage[0].tested == 2

    # A check that is already running finishes its endpoint: the stop is never mid-check.
    def test_a_running_step_is_not_cut_off(self):
        stop = {"now": False}

        @_unregistered
        class TwoRequests(Check):
            id = "two"

            def run(self, endpoint, ctx):
                ctx.client.request("POST", ctx.url(endpoint.path))
                stop["now"] = True  # asked to stop halfway through this endpoint
                ctx.client.request("DELETE", ctx.url(endpoint.path))  # the clean-up still goes out
                return iter(())

        methods: list[str] = []
        run_scan(_endpoints(3), [TwoRequests], _ctx(lambda r: methods.append(r.method) or httpx.Response(200)),
                 should_stop=lambda: "cancelled" if stop["now"] else None)

        assert methods == ["POST", "DELETE"]

    # Without the hooks nothing changes.
    def test_no_hooks_runs_everything(self):
        result = run_scan(_endpoints(2), [AuthRequired], _ctx(lambda r: httpx.Response(401)))

        assert result.incomplete is False and result.coverage[0].tested == 2


SPEC = minimal_spec(paths={"/a": {"get": {"responses": {"200": {"$ref": "#/components/responses/Ok"}}}}},
                    components={"responses": {"Ok": {"description": "ok"}}})


class TestLoadSpecText:
    def test_json_text_loads_with_refs_inlined(self):
        spec = load_spec_text(json.dumps(SPEC))

        assert spec["paths"]["/a"]["get"]["responses"]["200"] == {"description": "ok"}

    def test_yaml_text_loads(self):
        text = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200': {description: ok}\n"

        assert "/a" in load_spec_text(text)["paths"]

    def test_errors_name_the_source(self):
        with pytest.raises(SpecError, match="^upload.yaml: the spec is empty"):
            load_spec_text("  ", "upload.yaml")

    # An uploaded spec can't make the engine fetch anything either.
    def test_external_refs_are_refused(self):
        spec = minimal_spec(paths={"/a": {"get": {"responses": {"200": {"$ref": "http://169.254.169.254/x#/r"}}}}})

        with pytest.raises(SpecError, match="outside the spec"):
            load_spec_text(json.dumps(spec))


def _bomb(depth: int) -> str:
    lines = ["openapi: 3.0.3", "info: {title: t, version: '1'}", "paths: {}", "x-a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    lines += [f"x-a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]" for i in range(1, depth + 1)]
    return "\n".join(lines)


class TestYamlAliases:
    # A few hundred bytes that would expand to 10^9 nodes are refused before anything expands.
    def test_an_alias_bomb_is_refused_at_once(self):
        with pytest.raises(SpecError, match="YAML aliases"):
            load_spec_text(_bomb(8), allow_yaml_aliases=False)

    def test_the_same_refusal_through_load_spec(self, tmp_path):
        path = tmp_path / "bomb.yaml"
        path.write_text(_bomb(8), encoding="utf-8")

        with pytest.raises(SpecError, match="YAML aliases"):
            load_spec(str(path), allow_yaml_aliases=False)

    # The CLI's default is unchanged: a spec that uses an alias or two still loads.
    def test_aliases_are_allowed_by_default(self):
        assert load_spec_text(_bomb(1))["x-a1"][0] == ["x"] * 10

    # JSON can't contain aliases, so "&" and "*" inside JSON strings are fine.
    def test_json_with_ampersands_and_stars_is_not_mistaken_for_aliases(self):
        spec = minimal_spec(info={"title": "R&D *beta* &x *x", "version": "1"})

        assert load_spec_text(json.dumps(spec), allow_yaml_aliases=False)["info"]["title"] == "R&D *beta* &x *x"

    # YAML without aliases, including "&" and "*" in quoted strings, loads.
    def test_yaml_without_aliases_loads(self):
        text = "openapi: 3.0.3\ninfo: {title: 'R&D *beta*', version: '1'}\npaths: {}\n"

        assert load_spec_text(text, allow_yaml_aliases=False)["info"]["title"] == "R&D *beta*"
