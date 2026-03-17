"""Integration tests for GET /threats endpoints.

Verifies nested S1 response shape (threatInfo / agentDetectionInfo / agentRealtimeInfo)
and that internal fields (notes, timeline) are never exposed in list/single responses.
"""
from fastapi.testclient import TestClient

_INTERNAL = {"notes", "timeline"}
_REQUIRED_TOP_LEVEL = {"id", "threatInfo", "agentDetectionInfo", "agentRealtimeInfo",
                       "indicators", "mitigationStatus", "whiteningOptions"}
_REQUIRED_THREAT_INFO = {"threatName", "classification", "confidenceLevel",
                         "mitigationStatus", "incidentStatus", "analystVerdict",
                         "sha1", "createdAt", "filePath"}


class TestListThreats:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/threats").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/threats", headers=auth_headers)
        assert resp.status_code == 200
        assert "data" in resp.json()
        assert "pagination" in resp.json()

    def test_nested_structure_present(self, client: TestClient, auth_headers: dict) -> None:
        threat = client.get("/web/api/v2.1/threats", headers=auth_headers).json()["data"][0]
        for key in _REQUIRED_TOP_LEVEL:
            assert key in threat, f"Missing top-level key: {key}"
        for key in _REQUIRED_THREAT_INFO:
            assert key in threat["threatInfo"], f"Missing threatInfo key: {key}"

    def test_no_internal_fields(self, client: TestClient, auth_headers: dict) -> None:
        for threat in client.get("/web/api/v2.1/threats", headers=auth_headers).json()["data"]:
            for field in _INTERNAL:
                assert field not in threat

    def test_filter_by_classification(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/threats", headers=auth_headers,
                          params={"classifications": "Malware"})
        assert resp.status_code == 200
        for t in resp.json()["data"]:
            assert t["threatInfo"]["classification"] == "Malware"

    def test_filter_by_mitigation_status(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/threats", headers=auth_headers,
                          params={"mitigationStatuses": "mitigated"})
        for t in resp.json()["data"]:
            assert t["threatInfo"]["mitigationStatus"] == "mitigated"


class TestGetThreat:
    def test_returns_single_threat(self, client: TestClient, auth_headers: dict) -> None:
        tid = client.get("/web/api/v2.1/threats", headers=auth_headers).json()["data"][0]["id"]
        resp = client.get(f"/web/api/v2.1/threats/{tid}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == tid

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        assert client.get("/web/api/v2.1/threats/nope", headers=auth_headers).status_code == 404

    def test_no_internal_fields_in_single(self, client: TestClient, auth_headers: dict) -> None:
        tid = client.get("/web/api/v2.1/threats", headers=auth_headers).json()["data"][0]["id"]
        threat = client.get(f"/web/api/v2.1/threats/{tid}", headers=auth_headers).json()["data"]
        for field in _INTERNAL:
            assert field not in threat


class TestThreatTimeline:
    def test_returns_list_response(self, client: TestClient, auth_headers: dict) -> None:
        tid = client.get("/web/api/v2.1/threats", headers=auth_headers).json()["data"][0]["id"]
        resp = client.get(f"/web/api/v2.1/threats/{tid}/timeline", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)
