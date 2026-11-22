"""The Supabase table client (against a fake PostgREST) and the request guards."""

import json
from datetime import datetime, timezone

import httpx
import pytest

from apifuzz_web.config import ConfigError, load_config
from apifuzz_web.guards import RateLimiter, client_ip
from apifuzz_web.store import ScanRow, StoreError, SupabaseStore

SECRET = "sb_secret_test"


def row(**overrides) -> ScanRow:
    values = dict(user_id="u1", user_email="a@example.test", target="http://lab", spec_url="http://lab/openapi.json",
                  checks=["bola"], status="done", requests_sent=3, created_at="2026-11-21T15:00:00+00:00",
                  report={"findings": []})
    values.update(overrides)
    return ScanRow(**values)


def fake_postgrest(answer):
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer(request)

    return seen, SupabaseStore("https://project.supabase.co", SECRET, transport=httpx.MockTransport(handle))


def test_the_secret_key_goes_in_apikey_only():
    seen, store = fake_postgrest(lambda r: httpx.Response(201))
    store.add(row())
    request = seen[0]
    assert request.url.path == "/rest/v1/scans" and request.method == "POST"
    assert request.headers["apikey"] == SECRET and "authorization" not in request.headers
    assert json.loads(request.content)["user_id"] == "u1"


def test_list_filters_by_owner_unless_admin():
    seen, store = fake_postgrest(lambda r: httpx.Response(200, json=[]))
    store.list("u1")
    store.list(None)
    assert seen[0].url.params["user_id"] == "eq.u1" and seen[0].url.params["status"] == "eq.done"
    assert "user_id" not in seen[1].url.params


def test_count_reads_the_total_postgrest_reports():
    seen, store = fake_postgrest(lambda r: httpx.Response(200, headers={"Content-Range": "*/4"}))
    since = datetime(2026, 11, 21, tzinfo=timezone.utc)
    assert store.count_since(since, "u1") == 4
    params = seen[0].url.params
    assert params["created_at"] == "gte.2026-11-21T00:00:00+00:00"  # the + survives the query string
    assert params["requests_sent"] == "gt.0" and params["user_id"] == "eq.u1"


def test_get_skips_the_database_for_a_malformed_id():
    seen, store = fake_postgrest(lambda r: httpx.Response(200, json=[]))
    assert store.get("1 or 1=1") is None
    assert seen == []


def test_a_database_error_is_a_store_error_without_its_body():
    _, store = fake_postgrest(lambda r: httpx.Response(500, text="secret internals"))
    with pytest.raises(StoreError) as caught:
        store.list("u1")
    assert "secret" not in str(caught.value)


def test_a_count_without_a_total_is_an_error():
    _, store = fake_postgrest(lambda r: httpx.Response(200))
    with pytest.raises(StoreError):
        store.count_since(datetime(2026, 11, 21, tzinfo=timezone.utc))


# ---- rate limiter ---------------------------------------------------------------------------


def test_sliding_window():
    limiter = RateLimiter(limit=3, window=60)
    assert [limiter.hit("k", now=t) for t in (0, 1, 2)] == [None, None, None]
    assert limiter.hit("k", now=3) == pytest.approx(57)  # wait until the first hit leaves the window
    assert limiter.hit("other", now=3) is None
    assert limiter.hit("k", now=60.5) is None


def test_the_key_table_cannot_grow_without_end():
    limiter = RateLimiter(limit=1, window=60, max_keys=100)
    for i in range(1000):
        limiter.hit(f"k{i}", now=float(i))
    assert len(limiter._hits) <= 100


def test_client_address_behind_a_proxy_is_the_last_forwarded_entry():
    scope = {"client": ("10.0.0.1", 1234), "headers": [(b"x-forwarded-for", b"6.6.6.6, 203.0.113.9")]}
    assert client_ip(scope, behind_proxy=True) == "203.0.113.9"  # what the proxy saw
    assert client_ip(scope, behind_proxy=False) == "10.0.0.1"  # without a proxy the header is ignored


# ---- settings -------------------------------------------------------------------------------


def test_settings_must_be_sane():
    base = {"SUPABASE_URL": "https://project.supabase.co"}
    assert load_config(base).targets[0].base_url == "http://127.0.0.1:8000"
    assert load_config(base).targets[0].health_url == "http://127.0.0.1:8000/health"
    assert load_config(base).wake_timeout == 30
    assert load_config({**base, "TARGET_WAKE_SECONDS": "90"}).wake_timeout == 90
    for bad in [{}, {"SUPABASE_URL": "http://project.supabase.co"}, {"SUPABASE_URL": "https://p.supabase.co/x"},
                {**base, "LAB_SPEC_URL": "http://169.254.169.254/"}, {**base, "SCANS_PER_DAY": "lots"},
                {**base, "SCANS_PER_DAY": "0"}, {**base, "LAB_URL": "http://u:p@lab"}]:
        with pytest.raises(ConfigError):
            load_config(bad)


def test_lab_accounts_become_engine_settings_only():
    config = load_config({"SUPABASE_URL": "https://p.supabase.co", "LAB_USER_A": "alice", "LAB_PASSWORD_A": "pw",
                          "SUPABASE_SECRET_KEY": "sb_secret_x"})
    env = config.targets[0].engine_env
    assert env == {"APIFUZZ_USER_A": "alice", "APIFUZZ_PASSWORD_A": "pw"}
    assert "sb_secret_x" not in repr(config)  # secrets stay out of logs and tracebacks
