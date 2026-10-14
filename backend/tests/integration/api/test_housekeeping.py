"""A long-running instance forgets what the products forget, on their schedule.

2.6.0 made ``/_dev/reset`` carry issued tokens across, so an SDK's cached
token survives a reset between tests — and with nothing ever deleting a
token, every token issued since the process started was carried across
every reset, expired or not, until a cap of 5,000 evicted the oldest entry
whether or not it was still live. A soak of 3,600 mixed requests left
about 40 tokens per Entra mount behind, none ever freed. The sweep applies
each product's lifetime; the server runs it every minute and the reset
runs it first.
"""
from __future__ import annotations

import base64
import time

import pytest
from fastapi.testclient import TestClient

from infrastructure import housekeeping
from main import app
from repository.store import store
from tests.clock import Clock

ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
ES = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}


def _cs_token(client: TestClient) -> str:
    return str(client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
    }).json()["access_token"])


def _graph_token(client: TestClient) -> str:
    return str(client.post("/graph/oauth2/v2.0/token", data={
        "client_id": "graph-mock-admin-client", "client_secret": "graph-mock-admin-secret",
        "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default",
    }).json()["access_token"])


def _sentinel_token(client: TestClient) -> str:
    return str(client.post("/sentinel/oauth2/v2.0/token", data={
        "client_id": "sentinel-mock-client-id", "client_secret": "sentinel-mock-client-secret",
        "grant_type": "client_credentials", "scope": "https://management.azure.com/.default",
    }).json()["access_token"])


def test_expired_tokens_do_not_ride_every_reset(client: TestClient, clock: Clock) -> None:
    old = [_cs_token(client), _graph_token(client), _sentinel_token(client)]
    clock.advance(days=1, seconds=3600)
    live = _cs_token(client)

    assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

    assert store.get("cs_oauth_tokens", old[0]) is None
    assert store.get("graph_oauth_tokens", old[1]) is None
    assert store.get("sentinel_oauth_tokens", old[2]) is None
    response = client.get("/cs/devices/queries/devices/v1",
                          headers={"Authorization": f"Bearer {live}"})
    assert response.status_code == 200


def test_a_recently_expired_token_still_says_expired(client: TestClient, clock: Clock) -> None:
    """Held for a day past expiry, it keeps the product's "expired" answer."""
    token = _graph_token(client)
    clock.advance(3600)
    housekeeping.sweep()

    response = client.get("/graph/v1.0/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["error"]["message"]


def test_an_elasticsearch_token_survives_a_reset(client: TestClient) -> None:
    token = client.post("/elastic/_security/oauth2/token", headers=ES,
                        json={"grant_type": "client_credentials"}).json()["access_token"]

    assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

    response = client.get("/elastic/_cluster/health", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_the_sweep_covers_every_rule(client: TestClient, clock: Clock) -> None:
    _cs_token(client)
    client.post("/splunk/services/auth/login?output_mode=json",
                data={"username": "admin", "password": "mockdr-admin"})
    client.post("/elastic/.alerts-security.alerts-default/_search", headers=ES,
                params={"scroll": "1m"}, json={"size": 1})
    clock.advance(days=2)

    freed = housekeeping.sweep()

    assert freed["bearer_tokens"] >= 1
    assert freed["splunk_sessions"] >= 1
    assert freed["es_search_contexts"] >= 1
    assert store.count("cs_oauth_tokens") == 0


def test_the_server_sweeps_while_it_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    swept: list[float] = []
    monkeypatch.setattr(housekeeping, "SWEEP_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(housekeeping, "sweep", lambda now=None: swept.append(1) or {})

    with TestClient(app):
        deadline = time.monotonic() + 2
        while not swept and time.monotonic() < deadline:
            time.sleep(0.02)

    assert swept, "the lifespan never ran the sweep"
