"""Integration tests for Sentinel ARM response format validation."""
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


class TestARMEnvelopeFormat:
    """Verify ARM envelope structure on all endpoint families."""

    def _assert_arm_resource(self, resource: dict) -> None:
        assert "id" in resource, "Missing 'id'"
        assert "name" in resource, "Missing 'name'"
        assert "type" in resource, "Missing 'type'"
        assert "properties" in resource, "Missing 'properties'"

    def _assert_arm_list(self, body: dict) -> None:
        assert "value" in body, "Missing 'value'"
        assert isinstance(body["value"], list)

    def test_incidents_list_format(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(client))
        self._assert_arm_list(resp.json())
        if resp.json()["value"]:
            self._assert_arm_resource(resp.json()["value"][0])

    def test_watchlists_list_format(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/watchlists", headers=_auth(client))
        self._assert_arm_list(resp.json())
        self._assert_arm_resource(resp.json()["value"][0])

    def test_alert_rules_list_format(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/alertRules", headers=_auth(client))
        self._assert_arm_list(resp.json())
        self._assert_arm_resource(resp.json()["value"][0])

    def test_threat_intel_list_format(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/threatIntelligence/main/indicators",
            headers=_auth(client),
        )
        self._assert_arm_list(resp.json())
        self._assert_arm_resource(resp.json()["value"][0])

    def test_data_connectors_list_format(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/dataConnectors", headers=_auth(client))
        self._assert_arm_list(resp.json())

    def test_operations_format(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}/providers/Microsoft.SecurityInsights/operations")
        assert resp.status_code == 200
        assert "value" in resp.json()

    def test_log_analytics_format(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityIncident | take 1"},
            headers=_auth(client),
        )
        body = resp.json()
        assert "tables" in body
        table = body["tables"][0]
        assert "name" in table
        assert "columns" in table
        assert "rows" in table
        for col in table["columns"]:
            assert "name" in col
            assert "type" in col

    def test_etag_present(self, client: TestClient) -> None:
        """Mutable resources should have etag."""
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(client))
        if resp.json()["value"]:
            inc = resp.json()["value"][0]
            assert "etag" in inc, "Incident missing etag"

    def test_api_version_accepted(self, client: TestClient) -> None:
        """All endpoints should accept api-version parameter."""
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents",
            params={"api-version": "2025-01-01-preview"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
