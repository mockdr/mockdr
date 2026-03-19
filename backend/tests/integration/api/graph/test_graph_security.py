"""Integration tests for Microsoft Graph Security API endpoints."""
from fastapi.testclient import TestClient


class TestGraphAlerts:
    """Tests for /graph/v1.0/security/alerts_v2."""

    def test_list_alerts_returns_40_alerts(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 40 security alerts (mapped from MDE)."""
        resp = client.get(
            "/graph/v1.0/security/alerts_v2",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 40

    def test_list_alerts_with_filter_by_severity(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$filter=severity eq 'high' should return only high-severity alerts."""
        resp = client.get(
            "/graph/v1.0/security/alerts_v2",
            params={"$filter": "severity eq 'high'"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        for alert in resp.json()["value"]:
            assert alert["severity"] == "high"

    def test_get_alert_returns_single(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/security/alerts_v2/{id} should return a single alert."""
        list_resp = client.get(
            "/graph/v1.0/security/alerts_v2",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        alert_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/security/alerts_v2/{alert_id}",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == alert_id
        assert "title" in body
        assert "severity" in body
        assert "status" in body

    def test_patch_alert_updates_status(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """PATCH /v1.0/security/alerts_v2/{id} should update the alert status."""
        list_resp = client.get(
            "/graph/v1.0/security/alerts_v2",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        alert_id = list_resp.json()["value"][0]["id"]

        resp = client.patch(
            f"/graph/v1.0/security/alerts_v2/{alert_id}",
            json={"status": "resolved", "classification": "truePositive"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "resolved"
        assert body["classification"] == "truePositive"

    def test_plan1_cannot_access_alerts(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for security alerts."""
        resp = client.get(
            "/graph/v1.0/security/alerts_v2",
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403


class TestGraphIncidents:
    """Tests for /graph/v1.0/security/incidents."""

    def test_list_incidents_returns_15(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 15 security incidents."""
        resp = client.get(
            "/graph/v1.0/security/incidents",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 15

    def test_get_incident_returns_single(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/security/incidents/{id} should return a single incident."""
        list_resp = client.get(
            "/graph/v1.0/security/incidents",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        incident_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/security/incidents/{incident_id}",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == incident_id
        assert "displayName" in body
        assert "severity" in body

    def test_plan1_cannot_access_incidents(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for security incidents."""
        resp = client.get(
            "/graph/v1.0/security/incidents",
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403


class TestGraphHunting:
    """Tests for POST /graph/v1.0/security/runHuntingQuery."""

    def test_hunting_returns_schema_and_results(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Hunting query should return Schema, Results, and Stats."""
        resp = client.post(
            "/graph/v1.0/security/runHuntingQuery",
            json={"Query": "DeviceProcessEvents | take 10"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "Schema" in body
        assert "Results" in body
        assert "Stats" in body
        assert isinstance(body["Schema"], list)
        assert isinstance(body["Results"], list)
        assert len(body["Results"]) >= 1

    def test_plan1_cannot_hunt(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for hunting queries."""
        resp = client.post(
            "/graph/v1.0/security/runHuntingQuery",
            json={"Query": "DeviceProcessEvents | take 10"},
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403

    def test_dfb_cannot_hunt(
        self, client: TestClient,
    ) -> None:
        """Defender for Business token should receive 403 for hunting (requires plan2)."""
        # Obtain a DfB token
        token_resp = client.post(
            "/graph/oauth2/v2.0/token",
            data={
                "client_id": "graph-mock-smb-client",
                "client_secret": "graph-mock-smb-secret",
                "grant_type": "client_credentials",
            },
        )
        assert token_resp.status_code == 200
        dfb_headers = {"Authorization": f"Bearer {token_resp.json()['access_token']}"}

        resp = client.post(
            "/graph/v1.0/security/runHuntingQuery",
            json={"Query": "DeviceProcessEvents | take 10"},
            headers=dfb_headers,
        )
        assert resp.status_code == 403


class TestGraphSecureScores:
    """Tests for /graph/v1.0/security/secureScores."""

    def test_list_secure_scores_returns_30_daily(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 30 daily secure score snapshots."""
        resp = client.get(
            "/graph/v1.0/security/secureScores",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 30
        score = body["value"][0]
        assert "currentScore" in score
        assert "maxScore" in score
        assert "controlScores" in score


class TestGraphTiIndicators:
    """Tests for /graph/v1.0/security/tiIndicators."""

    def test_list_ti_indicators_returns_20(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 20 TI indicators (mapped from MDE)."""
        resp = client.get(
            "/graph/v1.0/security/tiIndicators",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert len(body["value"]) == 20

    def test_create_ti_indicator(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST /v1.0/security/tiIndicators should create a new indicator."""
        resp = client.post(
            "/graph/v1.0/security/tiIndicators",
            json={
                "action": "block",
                "description": "Test indicator",
                "indicatorValue": "evil.example.com",
                "indicatorType": "domainName",
                "targetProduct": "Microsoft Defender ATP",
                "threatType": "Malware",
                "tlpLevel": "amber",
            },
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "block"
        assert body["indicatorValue"] == "evil.example.com"
        assert "id" in body

    def test_delete_ti_indicator(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """DELETE /v1.0/security/tiIndicators/{id} should return 204."""
        # Get an existing indicator
        list_resp = client.get(
            "/graph/v1.0/security/tiIndicators",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        indicator_id = list_resp.json()["value"][0]["id"]

        resp = client.delete(
            f"/graph/v1.0/security/tiIndicators/{indicator_id}",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 204
