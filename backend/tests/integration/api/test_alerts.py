"""Integration tests for GET /cloud-detection/alerts endpoints.

Verifies response shape and required nested fields matching the real SentinelOne
swagger 2.1 API structure for /cloud-detection/alerts.

Alert top-level fields (swagger-compliant):
  alertInfo, ruleInfo, sourceProcessInfo, agentDetectionInfo,
  containerInfo, kubernetesInfo, sourceParentProcessInfo, targetProcessInfo

Key nested field notes:
  - severity lives in ruleInfo (not alertInfo)
  - no top-level id field
  - no agentRealtimeInfo field
"""
from fastapi.testclient import TestClient

_REQUIRED_TOP = {
    "alertInfo", "ruleInfo", "sourceProcessInfo", "agentDetectionInfo",
    "containerInfo", "kubernetesInfo", "sourceParentProcessInfo", "targetProcessInfo",
}

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_VALID_STATUSES = {"Unresolved", "In progress", "Resolved"}


class TestListAlerts:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/cloud-detection/alerts").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        alert = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers).json()["data"][0]
        for field in _REQUIRED_TOP:
            assert field in alert, f"Required top-level field '{field}' missing from alert"
        # alertInfo sub-fields (swagger-defined)
        for sub in ("alertId", "analystVerdict", "incidentStatus", "createdAt", "updatedAt",
                    "eventType", "hitType", "reportedAt"):
            assert sub in alert["alertInfo"], f"alertInfo.{sub} missing"
        # ruleInfo sub-fields (severity is here, not in alertInfo)
        assert "name" in alert["ruleInfo"], "ruleInfo.name missing"
        assert "severity" in alert["ruleInfo"], "ruleInfo.severity missing"
        # agentDetectionInfo
        assert "siteId" in alert["agentDetectionInfo"], "agentDetectionInfo.siteId missing"

    def test_severity_is_valid(self, client: TestClient, auth_headers: dict) -> None:
        alert = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers).json()["data"][0]
        assert alert["ruleInfo"]["severity"] in _VALID_SEVERITIES

    def test_incident_status_is_valid(self, client: TestClient, auth_headers: dict) -> None:
        alert = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers).json()["data"][0]
        assert alert["alertInfo"]["incidentStatus"] in _VALID_STATUSES



class TestAlertToAgentPivot:
    """An alert must name an agent the API can actually resolve.

    ``agentRealtimeInfo.id`` carried the agent's *uuid*, so the standard
    SOAR pivot — read an alert, look up the endpoint it fired on — returned
    404 for every alert in the store.
    """

    def test_alert_agent_id_resolves_to_an_agent(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        alerts = client.get(
            "/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
        ).json()["data"]

        for alert in alerts:
            agent_id = alert["agentRealtimeInfo"]["id"]
            resp = client.get(f"/web/api/v2.1/agents/{agent_id}", headers=auth_headers)
            assert resp.status_code == 200, f"alert names unknown agent {agent_id}"

    def test_agent_id_is_not_the_uuid(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        alert = client.get(
            "/web/api/v2.1/cloud-detection/alerts?limit=1", headers=auth_headers,
        ).json()["data"][0]
        assert alert["agentRealtimeInfo"]["id"] != alert["agentDetectionInfo"]["uuid"]

    def test_agent_ids_filter_selects_by_agent_id(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        alert = client.get(
            "/web/api/v2.1/cloud-detection/alerts?limit=1", headers=auth_headers,
        ).json()["data"][0]
        agent_id = alert["agentRealtimeInfo"]["id"]

        resp = client.get(
            f"/web/api/v2.1/cloud-detection/alerts?agentIds={agent_id}",
            headers=auth_headers,
        ).json()

        assert resp["pagination"]["totalItems"] >= 1
        assert all(
            a["agentRealtimeInfo"]["id"] == agent_id for a in resp["data"]
        )
