"""Seed data ages, and ``MOCKDR_RESEED_INTERVAL`` is how a long-lived instance keeps up.

Seed records are dated relative to the moment they were seeded. That is
deliberate — a tenant's data ages too — but a real tenant keeps receiving
new data and the mock does not. Measured on 2.6.0 with the clock moved
forward (``tests/clock.py``): one day in, Splunk's ``earliest=-24h`` counts
0 of 170 events and Falcon's ``last_seen:>'now-1d'`` 0 of 10 hosts; a week
in, every 7-day window is empty; 31 days in, Graph hunting's default 30-day
``Timespan`` returns 0 of 353 rows; and 181 days in, the seeded SentinelOne
API tokens have expired. The public demo stays up for days.

The decision: leave the ageing as product behaviour (a stored timestamp
never moves, the determinism promise — same seed, same clock, same answer —
holds), and re-seed on a schedule where an instance must keep looking
current: ``MOCKDR_RESEED_INTERVAL``, set in render.yaml.
"""
from __future__ import annotations

import base64
import threading
import time

import pytest
from fastapi.testclient import TestClient

import config
from application.dev.commands import reset
from infrastructure import housekeeping
from main import app
from repository.store import store
from tests.clock import Clock

SPLUNK = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _last_day(client: TestClient) -> int:
    response = client.post("/splunk/services/search/jobs?output_mode=json", headers=SPLUNK, data={
        "search": "search index=* earliest=-24h | stats count", "exec_mode": "oneshot",
    })
    return int(response.json()["results"][0]["count"])


def test_a_day_old_seed_has_nothing_in_the_last_day_until_reseeded(
    client: TestClient, clock: Clock,
) -> None:
    assert _last_day(client) > 0
    clock.advance(days=1, seconds=60)
    assert _last_day(client) == 0  # as a tenant nobody writes to would

    reset()
    assert _last_day(client) > 0


def test_the_seeded_api_token_outlives_half_a_year_only_by_reseeding(
    client: TestClient, clock: Clock,
) -> None:
    clock.advance(days=181)
    assert client.get("/web/api/v2.1/agents", headers=ADMIN).status_code == 401
    reset()
    assert client.get("/web/api/v2.1/agents", headers=ADMIN).status_code == 200


def test_process_start_times_move_with_the_seed(client: TestClient, clock: Clock) -> None:
    """Falcon process details were dated from import time, through every re-seed."""
    def headers() -> dict[str, str]:
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    device = client.get("/cs/devices/queries/devices/v1?limit=1", headers=headers()).json()
    pid = f"pid:{device['resources'][0]}:42"

    def started() -> float:
        body = client.get(f"/cs/processes/entities/processes/v1?ids={pid}",
                          headers=headers()).json()
        stamp = body["resources"][0]["start_timestamp"]
        return time.mktime(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))

    before = started()
    clock.advance(days=10)
    reset()
    assert abs(started() - before - 10 * 86400) < 5


@pytest.mark.parametrize(("text", "seconds"), [
    ("", 0), ("90", 90), ("90s", 90), ("15m", 900), ("12h", 43200), ("1d", 86400), ("x", 0),
])
def test_the_interval_reads_like_a_duration(text: str, seconds: float) -> None:
    assert config._duration_seconds(text) == seconds


def test_the_server_reseeds_on_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "RESEED_INTERVAL_SECONDS", 0.05)
    seeded = store.seeded_at

    with TestClient(app):
        deadline = time.monotonic() + 2
        while store.seeded_at == seeded and time.monotonic() < deadline:
            time.sleep(0.02)

    assert store.seeded_at != seeded, "MOCKDR_RESEED_INTERVAL never re-seeded"


def test_no_reseed_unless_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[float] = []
    monkeypatch.setattr(config, "RESEED_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(housekeeping, "reseed_periodically", lambda interval: calls.append(1))
    with TestClient(app):
        pass
    assert calls == []


def test_a_reader_never_sees_the_store_half_reset() -> None:
    """A reset under traffic: every read sees the old data set or the new one."""
    expected = store.count("agents")
    seen: list[int] = []
    done = threading.Event()

    def read() -> None:
        while not done.is_set():
            seen.append(store.count("agents"))

    reader = threading.Thread(target=read)
    reader.start()
    try:
        for _ in range(10):
            reset()
    finally:
        done.set()
        reader.join()

    assert seen and set(seen) == {expected}, sorted(set(seen))
