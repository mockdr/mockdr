"""Kibana's console proxy reaches this instance's Elasticsearch and nothing else."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ES_AUTH = ("elastic", "mock-elastic-password")


@pytest.mark.parametrize("path", [
    "../web/api/v2.1/system/info",
    "%2e%2e/web/api/v2.1/system/info",
    "_cat/../../../web/api/v2.1/system/info",
])
def test_console_proxy_cannot_climb_out_of_elasticsearch(client: TestClient, path: str) -> None:
    resp = client.post(
        "/kibana/api/console/proxy", params={"path": path, "method": "GET"},
        auth=ES_AUTH, headers={"kbn-xsrf": "true"},
    )
    # Elasticsearch's answer for a path it cannot route, never SentinelOne's.
    assert "errors" not in resp.json()
    assert "Authentication Failed" not in resp.text


def test_console_proxy_still_reaches_elasticsearch(client: TestClient) -> None:
    resp = client.post(
        "/kibana/api/console/proxy", params={"path": "/_cluster/health", "method": "GET"},
        auth=ES_AUTH, headers={"kbn-xsrf": "true"},
    )
    assert resp.status_code == 200
    assert "cluster_name" in resp.json()
