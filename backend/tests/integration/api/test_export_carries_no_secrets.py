"""GET /_dev/export and POST /_dev/import, as a visitor can use them.

The admin token is a documented constant, so the export is readable by anyone
who can reach the instance: it must not carry the real-vendor credentials the
recording proxy holds. And an import that cannot be loaded must be refused
before it empties the store everybody is using.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

import application.proxy._state as proxy_state
from domain.proxy_recording import ProxyConfig

PROXY = "/web/api/v2.1/_dev/proxy/config"


@pytest.fixture(autouse=True)
def proxy_off() -> Iterator[None]:
    """Every test starts and ends with the proxy off."""
    proxy_state._config = ProxyConfig(mode="off")
    yield
    proxy_state._config = ProxyConfig(mode="off")


def test_export_leaves_out_upstream_credentials(client: TestClient, auth_headers: dict) -> None:
    body = {"mode": "off", "vendors": [{
        "vendor": "s1", "base_url": "https://tenant.sentinelone.example",
        "auth": {"type": "api_token", "token": "REAL-SECRET-1"}, "enabled": True,
    }]}
    assert client.post(PROXY, headers=auth_headers, json=body).status_code == 200

    snapshot = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
    assert "REAL-SECRET-1" not in str(snapshot)

    # Importing it back into the same instance keeps the configured secret.
    assert client.post(
        "/web/api/v2.1/_dev/import", headers=auth_headers, json=snapshot,
    ).status_code == 200
    assert proxy_state._config.vendors["s1"].auth.token == "REAL-SECRET-1"  # type: ignore[union-attr]


def test_a_malformed_snapshot_is_refused_before_the_store_is_cleared(
    client: TestClient, auth_headers: dict,
) -> None:
    before = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["pagination"]
    resp = client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json={"agents": 5})
    assert resp.status_code == 400
    after = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["pagination"]
    assert after["totalItems"] == before["totalItems"] > 0
