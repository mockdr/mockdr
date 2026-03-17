"""Integration tests for system endpoints.

GET /system/status         — unauthenticated health check
GET /system/info           — authenticated server version info
GET /system/configuration  — authenticated system configuration
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


class TestSystemStatus:
    """Tests for the public /system/status endpoint."""

    def test_status_returns_200(self, client: TestClient) -> None:
        resp = client.get(f"{BASE}/system/status")
        assert resp.status_code == 200

    def test_status_returns_data_envelope(self, client: TestClient) -> None:
        body = client.get(f"{BASE}/system/status").json()
        assert "data" in body

    def test_status_health_is_ok(self, client: TestClient) -> None:
        body = client.get(f"{BASE}/system/status").json()
        assert body["data"]["health"] == "ok"

    def test_status_does_not_require_auth(self, client: TestClient) -> None:
        # No auth headers — should still succeed
        resp = client.get(f"{BASE}/system/status")
        assert resp.status_code == 200

    def test_status_idempotent(self, client: TestClient) -> None:
        body1 = client.get(f"{BASE}/system/status").json()
        body2 = client.get(f"{BASE}/system/status").json()
        assert body1 == body2


class TestSystemInfo:
    """Tests for the authenticated /system/info endpoint."""

    def test_info_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/system/info", headers=auth_headers)
        assert resp.status_code == 200

    def test_info_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/system/info", headers=auth_headers).json()
        assert "data" in body

    def test_info_contains_server_version(self, client: TestClient, auth_headers: dict) -> None:
        data = client.get(f"{BASE}/system/info", headers=auth_headers).json()["data"]
        assert "serverVersion" in data
        assert isinstance(data["serverVersion"], str)
        assert len(data["serverVersion"]) > 0

    def test_info_contains_latest_agent_version(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        data = client.get(f"{BASE}/system/info", headers=auth_headers).json()["data"]
        assert "latestAgentVersion" in data
        assert isinstance(data["latestAgentVersion"], str)

    def test_info_contains_build_time(self, client: TestClient, auth_headers: dict) -> None:
        data = client.get(f"{BASE}/system/info", headers=auth_headers).json()["data"]
        assert "buildTime" in data

    def test_info_requires_auth(self, client: TestClient) -> None:
        resp = client.get(f"{BASE}/system/info")
        assert resp.status_code == 401


class TestSystemConfiguration:
    """Tests for the authenticated /system/configuration endpoint."""

    def test_configuration_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/system/configuration", headers=auth_headers)
        assert resp.status_code == 200

    def test_configuration_returns_data_envelope(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        body = client.get(f"{BASE}/system/configuration", headers=auth_headers).json()
        assert "data" in body

    def test_configuration_contains_enforcement_mode(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        data = client.get(f"{BASE}/system/configuration", headers=auth_headers).json()["data"]
        assert "enforcementMode" in data
        assert data["enforcementMode"] == "protect"

    def test_configuration_contains_log_level(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        data = client.get(f"{BASE}/system/configuration", headers=auth_headers).json()["data"]
        assert "logLevel" in data

    def test_configuration_contains_max_free_space(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        data = client.get(f"{BASE}/system/configuration", headers=auth_headers).json()["data"]
        assert "maxFreeSpaceForLog" in data
        assert isinstance(data["maxFreeSpaceForLog"], int)

    def test_configuration_requires_auth(self, client: TestClient) -> None:
        resp = client.get(f"{BASE}/system/configuration")
        assert resp.status_code == 401
