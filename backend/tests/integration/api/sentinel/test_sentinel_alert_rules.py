"""Integration tests for Sentinel analytics rule endpoints."""
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


class TestAlertRules:
    """Tests for alert rules CRUD."""

    def test_list_rules(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/alertRules", headers=_auth(client))
        assert resp.status_code == 200
        rules = resp.json()["value"]
        assert len(rules) >= 5  # pre-seeded

    def test_get_rule(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/alertRules/rule-mde-alerts",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert resp.json()["properties"]["displayName"] == "MDE Alert Ingestion"

    def test_create_rule(self, client: TestClient) -> None:
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/alertRules/test-rule-001",
            json={
                "kind": "Scheduled",
                "properties": {
                    "displayName": "Test Rule",
                    "severity": "High",
                    "query": "SecurityAlert | where Severity == 'High'",
                    "enabled": True,
                },
            },
            headers=_auth(client),
        )
        assert resp.status_code == 200

    def test_delete_rule(self, client: TestClient) -> None:
        headers = _auth(client)
        client.put(
            f"{SENTINEL_PREFIX}{_WS}/alertRules/test-del-rule",
            json={"kind": "Scheduled", "properties": {"displayName": "Delete Me"}},
            headers=headers,
        )
        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/alertRules/test-del-rule",
            headers=headers,
        )
        assert resp.status_code == 200
