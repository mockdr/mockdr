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

