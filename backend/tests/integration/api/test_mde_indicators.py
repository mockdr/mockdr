"""Integration tests for Microsoft Defender for Endpoint Indicators endpoints.

Verifies indicator listing, detail retrieval, create, update (PATCH),
delete, and batch operations.
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


def _get_first_indicator_id(client: TestClient, headers: dict) -> str:
    """Return the first indicator ID from the listing."""
    resp = client.get("/mde/api/indicators", headers=headers, params={"$top": 1})
    return resp.json()["value"][0]["indicatorId"]


class TestListIndicators:
    """Tests for GET /mde/api/indicators."""

    def test_list_indicators_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/indicators", headers=headers)
        assert resp.status_code == 200

    def test_odata_response_format(self, client: TestClient) -> None:
        """Response must have @odata.context and value array."""
        headers = _mde_auth(client)
        resp = client.get("/mde/api/indicators", headers=headers)
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_indicators_have_required_fields(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/indicators", headers=headers, params={"$top": 1})
        indicator = resp.json()["value"][0]
        required_fields = [
            "indicatorId", "indicatorValue", "indicatorType",
            "action", "severity", "title",
        ]
        for field in required_fields:
            assert field in indicator, f"Required field '{field}' missing from indicator"


class TestGetIndicator:
    """Tests for GET /mde/api/indicators/{indicator_id}."""

    def test_get_single_indicator(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        indicator_id = _get_first_indicator_id(client, headers)
        resp = client.get(f"/mde/api/indicators/{indicator_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["indicatorId"] == indicator_id

    def test_nonexistent_indicator_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/indicators/nonexistent-id", headers=headers)
        assert resp.status_code == 404


class TestCreateIndicator:
    """Tests for POST /mde/api/indicators."""

    def test_create_indicator(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.post(
            "/mde/api/indicators",
            headers=headers,
            json={
                "indicatorValue": "evil-domain.example.com",
                "indicatorType": "DomainName",
                "action": "AlertAndBlock",
                "title": "Test Indicator",
                "description": "Test indicator for integration tests",
                "severity": "High",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "indicatorId" in body
        assert body["indicatorValue"] == "evil-domain.example.com"
        assert body["indicatorType"] == "DomainName"
        assert body["action"] == "AlertAndBlock"

    def test_created_indicator_appears_in_listing(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        create_resp = client.post(
            "/mde/api/indicators",
            headers=headers,
            json={
                "indicatorValue": "10.99.99.99",
                "indicatorType": "IpAddress",
                "action": "Alert",
                "title": "Test IP Indicator",
                "severity": "Low",
            },
        )
        new_id = create_resp.json()["indicatorId"]

        get_resp = client.get(f"/mde/api/indicators/{new_id}", headers=headers)
        assert get_resp.status_code == 200
        assert get_resp.json()["indicatorValue"] == "10.99.99.99"


class TestUpdateIndicator:
    """Tests for PATCH /mde/api/indicators/{indicator_id}."""

    def test_update_indicator(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        indicator_id = _get_first_indicator_id(client, headers)
        resp = client.patch(
            f"/mde/api/indicators/{indicator_id}",
            headers=headers,
            json={"severity": "High", "title": "Updated Title"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["severity"] == "High"
        assert body["title"] == "Updated Title"

    def test_update_nonexistent_indicator_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.patch(
            "/mde/api/indicators/nonexistent-id",
            headers=headers,
            json={"severity": "Low"},
        )
        assert resp.status_code == 404


class TestDeleteIndicator:
    """Tests for DELETE /mde/api/indicators/{indicator_id}."""

    def test_delete_indicator(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        indicator_id = _get_first_indicator_id(client, headers)
        resp = client.delete(f"/mde/api/indicators/{indicator_id}", headers=headers)
        assert resp.status_code == 204

        # Verify deletion
        get_resp = client.get(f"/mde/api/indicators/{indicator_id}", headers=headers)
        assert get_resp.status_code == 404

    def test_delete_nonexistent_indicator_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.delete("/mde/api/indicators/nonexistent-id", headers=headers)
        assert resp.status_code == 404


class TestBatchUpdateIndicators:
    """Tests for POST /mde/api/indicators/batchUpdate."""

    def test_batch_update_indicators(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        # Get two indicator IDs
        list_resp = client.get("/mde/api/indicators", headers=headers, params={"$top": 2})
        indicators = list_resp.json()["value"]
        indicator_values = [i["indicatorValue"] for i in indicators]

        resp = client.post(
            "/mde/api/indicators/batchUpdate",
            headers=headers,
            json={
                "indicatorValues": indicator_values,
                "action": "delete",
            },
        )
        assert resp.status_code == 200
