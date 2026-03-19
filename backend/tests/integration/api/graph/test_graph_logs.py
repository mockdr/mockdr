"""Integration tests for Microsoft Graph Audit Logs and Identity Protection endpoints."""
from fastapi.testclient import TestClient


class TestGraphSignInLogs:
    """Tests for /graph/v1.0/auditLogs/signIns."""

    def test_list_sign_in_logs_returns_200_entries(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 200 sign-in log entries."""
        resp = client.get(
            "/graph/v1.0/auditLogs/signIns",
            params={"$top": 200},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 200
        entry = body["value"][0]
        assert "userPrincipalName" in entry
        assert "appDisplayName" in entry
        assert "status" in entry

    def test_sign_in_logs_with_filter_by_date(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$filter by createdDateTime should return a subset of entries."""
        # Get all entries first to find a date range
        all_resp = client.get(
            "/graph/v1.0/auditLogs/signIns",
            headers=graph_admin_headers,
        )
        entries = all_resp.json()["value"]
        # Use a recent date from the data
        sample_date = entries[0]["createdDateTime"][:10]  # YYYY-MM-DD

        resp = client.get(
            "/graph/v1.0/auditLogs/signIns",
            params={
                "$filter": f"createdDateTime ge {sample_date}T00:00:00Z",
            },
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["value"]) >= 1

    def test_plan1_can_access_sign_in_logs(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 cannot access sign-in logs (requires plan2 or DfB)."""
        resp = client.get(
            "/graph/v1.0/auditLogs/signIns",
            headers=graph_p1_headers,
        )
        # Plan 1 is gated out of auditLogs/signIns
        assert resp.status_code == 403


class TestGraphAuditLogs:
    """Tests for /graph/v1.0/auditLogs/directoryAudits."""

    def test_list_audit_logs_returns_100_entries(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 100 directory audit log entries."""
        resp = client.get(
            "/graph/v1.0/auditLogs/directoryAudits",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 100
        entry = body["value"][0]
        assert "activityDisplayName" in entry
        assert "category" in entry
        assert "result" in entry


class TestGraphRiskyUsers:
    """Tests for /graph/v1.0/identityProtection/riskyUsers."""

    def test_list_risky_users_returns_5(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 5 risky users."""
        resp = client.get(
            "/graph/v1.0/identityProtection/riskyUsers",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 5
        user = body["value"][0]
        assert "riskLevel" in user
        assert "riskState" in user

    def test_get_risky_user_returns_single(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/identityProtection/riskyUsers/{id} should return a single risky user."""
        list_resp = client.get(
            "/graph/v1.0/identityProtection/riskyUsers",
            params={"$top": 1},
            headers=graph_admin_headers,
        )
        user_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/identityProtection/riskyUsers/{user_id}",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == user_id
        assert "riskLevel" in body

    def test_plan1_cannot_access_risky_users(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for identity protection."""
        resp = client.get(
            "/graph/v1.0/identityProtection/riskyUsers",
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403


class TestGraphRiskDetections:
    """Tests for /graph/v1.0/identityProtection/riskDetections."""

    def test_list_risk_detections_returns_15(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 15 risk detection events."""
        resp = client.get(
            "/graph/v1.0/identityProtection/riskDetections",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 15
        detection = body["value"][0]
        assert "riskEventType" in detection
        assert "riskLevel" in detection
        assert "userId" in detection
