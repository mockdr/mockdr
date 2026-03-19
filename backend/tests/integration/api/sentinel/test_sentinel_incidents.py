"""Integration tests for Sentinel incident endpoints."""
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


def _get_token(client: TestClient) -> str:
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={"client_id": "sentinel-mock-client-id",
              "client_secret": "sentinel-mock-client-secret",
              "grant_type": "client_credentials"},
    )
    return resp.json()["access_token"]


def _auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {_get_token(client)}"}


class TestListIncidents:
    """Tests for GET .../incidents."""

    def test_list_returns_200(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(client))
        assert resp.status_code == 200

    def test_response_has_value_array(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(client))
        body = resp.json()
        assert "value" in body
        assert isinstance(body["value"], list)
        assert len(body["value"]) > 0

    def test_incident_has_arm_envelope(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(client))
        inc = resp.json()["value"][0]
        assert "id" in inc
        assert "name" in inc
        assert "type" in inc
        assert "properties" in inc

    def test_incident_has_required_properties(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(client))
        props = resp.json()["value"][0]["properties"]
        required = ["title", "severity", "status", "owner", "createdTimeUtc",
                     "incidentNumber", "providerName", "additionalData"]
        for field in required:
            assert field in props, f"Missing required field '{field}'"

    def test_filter_by_status(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents",
            params={"$filter": "status eq 'New'"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        for inc in resp.json()["value"]:
            assert inc["properties"]["status"] == "New"

    def test_top_limits_results(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents",
            params={"$top": 3},
            headers=_auth(client),
        )
        assert len(resp.json()["value"]) <= 3


class TestCRUDIncidents:
    """Tests for incident CRUD operations."""

    def test_create_incident(self, client: TestClient) -> None:
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-inc-001",
            json={"properties": {
                "title": "Test Incident",
                "severity": "High",
                "status": "New",
            }},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert resp.json()["properties"]["title"] == "Test Incident"

    def test_get_incident(self, client: TestClient) -> None:
        headers = _auth(client)
        # Create
        client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-get-001",
            json={"properties": {"title": "Get Test", "severity": "Medium"}},
            headers=headers,
        )
        # Get
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-get-001",
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["properties"]["title"] == "Get Test"

    def test_update_incident(self, client: TestClient) -> None:
        headers = _auth(client)
        client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-update-001",
            json={"properties": {"title": "Original", "severity": "Low"}},
            headers=headers,
        )
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-update-001",
            json={"properties": {"status": "Closed", "classification": "TruePositive"}},
            headers=headers,
        )
        assert resp.status_code == 200
        props = resp.json()["properties"]
        assert props["status"] == "Closed"
        assert props["classification"] == "TruePositive"

    def test_delete_incident(self, client: TestClient) -> None:
        headers = _auth(client)
        client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-del-001",
            json={"properties": {"title": "Delete Me", "severity": "Low"}},
            headers=headers,
        )
        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/incidents/test-del-001",
            headers=headers,
        )
        assert resp.status_code == 200

    def test_get_nonexistent_returns_404(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents/nonexistent",
            headers=_auth(client),
        )
        assert resp.status_code == 404


class TestIncidentSubResources:
    """Tests for incident alerts, entities, comments."""

    def _get_first_incident_id(self, client: TestClient, headers: dict) -> str:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=headers)
        return resp.json()["value"][0]["name"]

    def test_list_incident_alerts(self, client: TestClient) -> None:
        headers = _auth(client)
        inc_id = self._get_first_incident_id(client, headers)
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/alerts",
            headers=headers,
        )
        assert resp.status_code == 200
        assert "value" in resp.json()

    def test_list_incident_entities(self, client: TestClient) -> None:
        headers = _auth(client)
        inc_id = self._get_first_incident_id(client, headers)
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/entities",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "entities" in body
        assert "metaData" in body

    def test_add_and_list_comments(self, client: TestClient) -> None:
        headers = _auth(client)
        inc_id = self._get_first_incident_id(client, headers)

        # Add comment
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/comments/test-comment-001",
            json={"properties": {"message": "Test comment from integration test"}},
            headers=headers,
        )
        assert resp.status_code == 200

        # List comments
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/comments",
            headers=headers,
        )
        assert resp.status_code == 200
        messages = [c["properties"]["message"] for c in resp.json()["value"]]
        assert "Test comment from integration test" in messages

    def test_run_playbook(self, client: TestClient) -> None:
        headers = _auth(client)
        inc_id = self._get_first_incident_id(client, headers)
        resp = client.post(
            f"{SENTINEL_PREFIX}{_WS}/incidents/{inc_id}/runPlaybook",
            headers=headers,
        )
        assert resp.status_code == 200
