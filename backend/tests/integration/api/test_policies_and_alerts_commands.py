"""Integration tests for policies and alert command endpoints.

Covers GET/PUT /policies and POST /cloud-detection/alerts/analyst-verdict,
/cloud-detection/alerts/incident.
"""
from fastapi.testclient import TestClient

# ── Policies ──────────────────────────────────────────────────────────────────

class TestGetPolicy:
    def test_returns_policy_data(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/policies", headers=auth_headers)
        assert resp.status_code == 200
        assert "data" in resp.json()

    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/policies").status_code == 401

    def test_filter_by_site_id_returns_data(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        sites = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"]
        site_id = sites[0]["id"]
        resp = client.get("/web/api/v2.1/policies", headers=auth_headers,
                          params={"siteId": site_id})
        assert resp.status_code == 200

    def test_filter_by_group_id_returns_data(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        groups = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"]
        group_id = groups[0]["id"]
        resp = client.get("/web/api/v2.1/policies", headers=auth_headers,
                          params={"groupId": group_id})
        assert resp.status_code == 200


class TestUpdatePolicy:
    def test_put_policy_returns_updated_data(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        sites = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"]
        site_id = sites[0]["id"]
        payload = {"data": {"autoVaccination": True}}
        resp = client.put("/web/api/v2.1/policies", headers=auth_headers,
                          json=payload, params={"siteId": site_id})
        assert resp.status_code == 200

    def test_put_requires_auth(self, client: TestClient) -> None:
        assert client.put("/web/api/v2.1/policies", json={}).status_code == 401


# ── Alert commands ────────────────────────────────────────────────────────────

class TestAlertCommands:
    def _first_alert_id(self, client: TestClient, auth_headers: dict) -> str:
        return client.get("/web/api/v2.1/cloud-detection/alerts",
                          headers=auth_headers).json()["data"][0]["alertInfo"]["alertId"]

    def test_set_analyst_verdict_returns_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = self._first_alert_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/cloud-detection/alerts/analyst-verdict",
                           headers=auth_headers,
                           json={"filter": {"ids": [aid]}, "data": {"verdict": "TRUE_POSITIVE"}})
        assert resp.status_code == 200
        assert "affected" in resp.json()["data"]

    def test_set_incident_status_returns_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = self._first_alert_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/cloud-detection/alerts/incident",
                           headers=auth_headers,
                           json={"filter": {"ids": [aid]}, "data": {"incidentStatus": "RESOLVED"}})
        assert resp.status_code == 200
        assert "affected" in resp.json()["data"]

    def test_commands_require_auth(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/cloud-detection/alerts/analyst-verdict",
                           json={"filter": {"ids": ["x"]}, "data": {}})
        assert resp.status_code == 401

    def test_filter_by_query(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                          params={"query": "detection"})
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)

    def test_filter_by_category(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                          params={"categories": "Injection"})
        assert resp.status_code == 200

    def test_filter_by_analyst_verdict(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                          params={"analystVerdicts": "UNDEFINED"})
        assert resp.status_code == 200

    def test_filter_by_agent_id(self, client: TestClient, auth_headers: dict) -> None:
        alerts = client.get("/web/api/v2.1/cloud-detection/alerts",
                            headers=auth_headers).json()["data"]
        agent_id = alerts[0]["agentDetectionInfo"]["uuid"]
        resp = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                          params={"agentIds": agent_id})
        assert resp.status_code == 200
        for alert in resp.json()["data"]:
            assert alert["agentDetectionInfo"]["uuid"] == agent_id
