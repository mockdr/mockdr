"""Integration tests for /_dev/* endpoints.

POST   /_dev/reset          — re-seed all data
POST   /_dev/scenario       — trigger named simulation
GET    /_dev/tokens         — list API tokens
GET    /_dev/stats          — collection counts
GET    /_dev/requests       — audit log
DELETE /_dev/requests       — clear audit log
GET    /_dev/rate-limit     — rate-limit config
POST   /_dev/rate-limit     — update rate-limit config
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


class TestReset:
    def test_reset_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/reset", headers=auth_headers)
        assert resp.status_code == 200

    def test_reset_returns_status_complete(self, client: TestClient, auth_headers: dict) -> None:
        body = client.post(f"{BASE}/_dev/reset", headers=auth_headers).json()
        assert body["data"]["status"] == "reset complete"


class TestScenario:
    def test_mass_infection(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/scenario", headers=auth_headers,
                          json={"scenario": "mass_infection"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["scenario"] == "mass_infection"
        assert "affected" in body["data"]

    def test_agent_offline(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/scenario", headers=auth_headers,
                          json={"scenario": "agent_offline"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["scenario"] == "agent_offline"
        assert "affected" in body["data"]

    def test_quiet_day(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/scenario", headers=auth_headers,
                          json={"scenario": "quiet_day"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["scenario"] == "quiet_day"
        assert "status" in body["data"]

    def test_apt_campaign(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/scenario", headers=auth_headers,
                          json={"scenario": "apt_campaign"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["scenario"] == "apt_campaign"
        assert "affected" in body["data"]

    def test_unknown_scenario_returns_error(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/scenario", headers=auth_headers,
                          json={"scenario": "not_a_real_scenario"})
        assert resp.status_code == 200
        assert "error" in resp.json()["data"]


class TestTokens:
    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/tokens", headers=auth_headers)
        assert resp.status_code == 200

    def test_returns_data_key(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/_dev/tokens", headers=auth_headers).json()
        assert "data" in body
        assert isinstance(body["data"], (list, dict))


class TestStats:
    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/stats", headers=auth_headers)
        assert resp.status_code == 200

    def test_contains_expected_keys(self, client: TestClient, auth_headers: dict) -> None:
        data = client.get(f"{BASE}/_dev/stats", headers=auth_headers).json()["data"]
        for key in ("agents", "threats", "alerts", "sites", "groups", "activities"):
            assert key in data, f"Missing stat key: {key}"

    def test_counts_are_ints(self, client: TestClient, auth_headers: dict) -> None:
        data = client.get(f"{BASE}/_dev/stats", headers=auth_headers).json()["data"]
        for key, val in data.items():
            assert isinstance(val, int), f"Count for {key} should be int"

    def test_agents_count_positive(self, client: TestClient, auth_headers: dict) -> None:
        data = client.get(f"{BASE}/_dev/stats", headers=auth_headers).json()["data"]
        assert data["agents"] > 0


class TestRequestAuditLog:
    def test_list_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/requests", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_has_data_key(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/_dev/requests", headers=auth_headers).json()
        assert "data" in body

    def test_clear_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.delete(f"{BASE}/_dev/requests", headers=auth_headers)
        assert resp.status_code == 200

    def test_clear_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        # Make some requests first
        client.get(f"{BASE}/agents", headers=auth_headers)
        body = client.delete(f"{BASE}/_dev/requests", headers=auth_headers).json()
        assert "data" in body


class TestRateLimit:
    def test_get_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/_dev/rate-limit", headers=auth_headers)
        assert resp.status_code == 200

    def test_get_has_enabled_and_rpm(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/_dev/rate-limit", headers=auth_headers).json()
        assert "enabled" in body
        assert "requestsPerMinute" in body

    def test_post_updates_config(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/rate-limit", headers=auth_headers,
                          json={"enabled": True, "requestsPerMinute": 120})
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is True
        assert body["requestsPerMinute"] == 120

    def test_post_disable_rate_limit(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/_dev/rate-limit", headers=auth_headers,
                          json={"enabled": False, "requestsPerMinute": 60})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
