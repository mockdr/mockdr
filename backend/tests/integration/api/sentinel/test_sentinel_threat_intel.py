"""Integration tests for Sentinel threat intelligence endpoints."""
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={"client_id": "sentinel-mock-client-id",
              "client_secret": "sentinel-mock-client-secret",
              "grant_type": "client_credentials"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestThreatIndicators:
    """Tests for TI indicator CRUD."""

    def test_list_indicators(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert "value" in resp.json()
        assert len(resp.json()["value"]) >= 3

    def test_create_indicator(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/createIndicator",
            json={"properties": {
                "displayName": "Test Indicator",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "patternType": "ipv4-addr",
                "source": "Test",
                "confidence": 80,
            }},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert resp.json()["properties"]["displayName"] == "Test Indicator"

    def test_query_indicators(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/queryIndicators",
            json={"keywords": "C2"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert "value" in resp.json()

    def test_get_metrics(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/metrics",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert "properties" in resp.json()

    def test_append_tags(self, client: TestClient) -> None:
        headers = _auth(client)
        # Get an indicator name
        list_resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators",
            headers=headers,
        )
        name = list_resp.json()["value"][0]["name"]

        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/appendTags",
            json={"indicatorNames": [name], "tags": ["test-tag"]},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_delete_indicator(self, client: TestClient) -> None:
        headers = _auth(client)
        # Create one first
        create_resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/createIndicator",
            json={"properties": {
                "displayName": "To Delete",
                "pattern": "[domain-name:value = 'delete.me']",
                "patternType": "domain-name",
            }},
            headers=headers,
        )
        name = create_resp.json()["name"]

        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators/{name}",
            headers=headers,
        )
        assert resp.status_code == 200
