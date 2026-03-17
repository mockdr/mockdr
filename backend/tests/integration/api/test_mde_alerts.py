"""Integration tests for Microsoft Defender for Endpoint Alerts endpoints.

Verifies alert listing, detail retrieval, update (PATCH), create by reference,
batch update, and OData response envelope format.
"""
from fastapi.testclient import TestClient


def _mde_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return MDE Bearer headers."""
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _get_first_alert_id(client: TestClient, headers: dict) -> str:
    """Return the first alert ID from the listing."""
    resp = client.get("/mde/api/alerts", headers=headers, params={"$top": 1})
    return resp.json()["value"][0]["alertId"]


class TestListAlerts:
    """Tests for GET /mde/api/alerts."""

    def test_list_alerts_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/alerts", headers=headers)
        assert resp.status_code == 200

    def test_odata_response_format(self, client: TestClient) -> None:
        """Response must have @odata.context and value array."""
        headers = _mde_auth(client)
        resp = client.get("/mde/api/alerts", headers=headers)
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_alerts_have_required_fields(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/alerts", headers=headers, params={"$top": 1})
        alert = resp.json()["value"][0]
        required_fields = [
            "alertId", "title", "description", "severity", "status",
            "category", "detectionSource", "machineId",
            "alertCreationTime",
        ]
        for field in required_fields:
            assert field in alert, f"Required field '{field}' missing from alert"

    def test_top_pagination(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/alerts", headers=headers, params={"$top": 3})
        assert len(resp.json()["value"]) == 3

    def test_skip_pagination(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        r1 = client.get("/mde/api/alerts", headers=headers, params={"$top": 5, "$skip": 0})
        r2 = client.get("/mde/api/alerts", headers=headers, params={"$top": 5, "$skip": 5})
        ids1 = {a["alertId"] for a in r1.json()["value"]}
        ids2 = {a["alertId"] for a in r2.json()["value"]}
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"


class TestGetAlert:
    """Tests for GET /mde/api/alerts/{alert_id}."""

    def test_get_single_alert(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        alert_id = _get_first_alert_id(client, headers)
        resp = client.get(f"/mde/api/alerts/{alert_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["alertId"] == alert_id

    def test_nonexistent_alert_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/alerts/nonexistent-alert-id", headers=headers)
        assert resp.status_code == 404


class TestUpdateAlert:
    """Tests for PATCH /mde/api/alerts/{alert_id}."""

    def test_update_alert_status(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        alert_id = _get_first_alert_id(client, headers)
        resp = client.patch(
            f"/mde/api/alerts/{alert_id}",
            headers=headers,
            json={"status": "InProgress"},
        )
        assert resp.status_code == 200
        # Verify the update persisted
        get_resp = client.get(f"/mde/api/alerts/{alert_id}", headers=headers)
        assert get_resp.json()["status"] == "InProgress"

    def test_update_alert_classification(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        alert_id = _get_first_alert_id(client, headers)
        resp = client.patch(
            f"/mde/api/alerts/{alert_id}",
            headers=headers,
            json={"classification": "TruePositive", "determination": "Malware"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["classification"] == "TruePositive"
        assert body["determination"] == "Malware"

    def test_update_alert_assigned_to(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        alert_id = _get_first_alert_id(client, headers)
        resp = client.patch(
            f"/mde/api/alerts/{alert_id}",
            headers=headers,
            json={"assignedTo": "analyst@acmecorp.internal"},
        )
        assert resp.status_code == 200
        assert resp.json()["assignedTo"] == "analyst@acmecorp.internal"

    def test_update_nonexistent_alert_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.patch(
            "/mde/api/alerts/nonexistent-alert-id",
            headers=headers,
            json={"status": "Resolved"},
        )
        assert resp.status_code == 404


class TestCreateAlertByReference:
    """Tests for POST /mde/api/alerts/createAlertByReference."""

    def test_create_alert_by_reference(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        # Get a machine ID to reference
        machines_resp = client.get("/mde/api/machines", headers=headers, params={"$top": 1})
        machine_id = machines_resp.json()["value"][0]["machineId"]

        resp = client.post(
            "/mde/api/alerts/createAlertByReference",
            headers=headers,
            json={
                "machineId": machine_id,
                "severity": "High",
                "title": "Test Alert",
                "description": "Test alert created by reference",
                "category": "SuspiciousActivity",
                "eventTime": "2026-03-13T12:00:00Z",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "alertId" in body
        assert body["title"] == "Test Alert"
        assert body["machineId"] == machine_id


class TestBatchUpdateAlerts:
    """Tests for POST /mde/api/alerts/batchUpdate."""

    def test_batch_update_alerts(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        # Get two alert IDs
        alerts_resp = client.get("/mde/api/alerts", headers=headers, params={"$top": 2})
        alert_ids = [a["alertId"] for a in alerts_resp.json()["value"]]

        resp = client.post(
            "/mde/api/alerts/batchUpdate",
            headers=headers,
            json={
                "alertIds": alert_ids,
                "status": "Resolved",
                "classification": "FalsePositive",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

        # Verify updates persisted
        for aid in alert_ids:
            get_resp = client.get(f"/mde/api/alerts/{aid}", headers=headers)
            assert get_resp.json()["status"] == "Resolved"
