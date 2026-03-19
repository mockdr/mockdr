"""Tests for role-based access control enforcement.

Three roles are tested:
- Admin (admin-token-0000-0000-000000000001): full access
- SOC Analyst (soc-analyst-token-000-000000000003): read + threat/alert triage + agent actions
- Viewer (viewer-token-0000-0000-000000000002): read-only
"""
from fastapi.testclient import TestClient

_ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
_SOC = {"Authorization": "ApiToken soc-analyst-token-000-000000000003"}
_VIEWER = {"Authorization": "ApiToken viewer-token-0000-0000-000000000002"}


class TestViewerReadOnly:
    """Viewer can read but cannot write."""

    def test_viewer_can_list_agents(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/agents", headers=_VIEWER).status_code == 200

    def test_viewer_can_list_threats(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/threats", headers=_VIEWER).status_code == 200

    def test_viewer_can_list_sites(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/sites", headers=_VIEWER)
        assert resp.status_code == 200

    def test_viewer_cannot_create_site(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/sites", headers=_VIEWER,
                           json={"data": {"name": "Forbidden Site"}})
        assert resp.status_code == 403

    def test_viewer_cannot_create_user(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/users", headers=_VIEWER,
                           json={"data": {"email": "x@x.com", "fullName": "X"}})
        assert resp.status_code == 403

    def test_viewer_cannot_delete_group(self, client: TestClient) -> None:
        resp = client.delete("/web/api/v2.1/groups/fake-id", headers=_VIEWER)
        assert resp.status_code == 403

    def test_viewer_cannot_create_exclusion(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/exclusions", headers=_VIEWER,
                           json={"data": {"type": "path", "value": "/tmp/x"}})
        assert resp.status_code == 403

    def test_viewer_cannot_create_webhook(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/webhooks", headers=_VIEWER,
                           json={"url": "http://localhost", "event_types": []})
        assert resp.status_code == 403

    def test_viewer_cannot_create_firewall_rule(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/firewall-control", headers=_VIEWER,
                           json={"data": {"name": "x"}})
        assert resp.status_code == 403

    def test_viewer_cannot_create_device_control_rule(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/device-control", headers=_VIEWER,
                           json={"data": {"ruleName": "x"}})
        assert resp.status_code == 403

    def test_viewer_cannot_create_ioc(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/threat-intelligence/iocs", headers=_VIEWER,
                           json={"type": "IPV4", "value": "1.2.3.4"})
        assert resp.status_code == 403

    def test_viewer_cannot_access_dev_endpoints(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/_dev/reset", headers=_VIEWER)
        assert resp.status_code == 403


class TestSOCAnalystPermissions:
    """SOC Analyst can triage threats/alerts and perform agent actions, but not admin ops."""

    def test_soc_can_list_agents(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/agents", headers=_SOC).status_code == 200

    def test_soc_can_set_threat_verdict(self, client: TestClient) -> None:
        # Get a threat ID
        threats = client.get("/web/api/v2.1/threats", headers=_SOC).json()["data"]
        if threats:
            tid = threats[0]["id"]
            resp = client.post("/web/api/v2.1/threats/analyst-verdict", headers=_SOC,
                               json={"filter": {"ids": [tid]}, "data": {"analystVerdict": "true_positive"}})
            assert resp.status_code == 200

    def test_soc_can_set_alert_verdict(self, client: TestClient) -> None:
        alerts = client.get("/web/api/v2.1/cloud-detection/alerts", headers=_SOC).json()["data"]
        if alerts:
            aid = alerts[0].get("id", alerts[0].get("alertInfo", {}).get("alertId", ""))
            resp = client.post("/web/api/v2.1/cloud-detection/alerts/analyst-verdict",
                               headers=_SOC,
                               json={"filter": {"ids": [aid]}, "data": {"analystVerdict": "TRUE_POSITIVE"}})
            assert resp.status_code == 200

    def test_soc_cannot_create_site(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/sites", headers=_SOC,
                           json={"data": {"name": "Forbidden"}})
        assert resp.status_code == 403

    def test_soc_cannot_create_user(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/users", headers=_SOC,
                           json={"data": {"email": "x@x.com"}})
        assert resp.status_code == 403

    def test_soc_cannot_delete_user(self, client: TestClient) -> None:
        resp = client.delete("/web/api/v2.1/users/fake-id", headers=_SOC)
        assert resp.status_code == 403

    def test_soc_cannot_create_exclusion(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/exclusions", headers=_SOC,
                           json={"data": {"type": "path", "value": "/tmp/x"}})
        assert resp.status_code == 403

    def test_soc_cannot_create_webhook(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/webhooks", headers=_SOC,
                           json={"url": "http://localhost", "event_types": []})
        assert resp.status_code == 403

    def test_soc_cannot_access_dev_endpoints(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/_dev/reset", headers=_SOC)
        assert resp.status_code == 403


class TestAdminFullAccess:
    """Admin can perform all operations."""

    def test_admin_can_create_and_delete_site(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/sites", headers=_ADMIN,
                           json={"data": {"name": "RBAC Test Site", "accountId": "1"}})
        assert resp.status_code == 200
        site_id = resp.json()["data"]["id"]
        del_resp = client.delete(f"/web/api/v2.1/sites/{site_id}", headers=_ADMIN)
        assert del_resp.status_code == 200

    def test_admin_can_create_user(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/users", headers=_ADMIN,
                           json={"data": {"email": "rbac-test@acmecorp.com", "fullName": "RBAC User"}})
        assert resp.status_code == 200

    def test_admin_can_access_dev_endpoints(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/_dev/stats", headers=_ADMIN)
        assert resp.status_code == 200


class TestForbiddenResponseFormat:
    """403 responses match the S1 error envelope."""

    def test_403_has_s1_error_envelope(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/sites", headers=_VIEWER,
                           json={"data": {"name": "X"}})
        assert resp.status_code == 403
        body = resp.json()
        assert "errors" in body
        assert body["data"] is None
        assert body["errors"][0]["code"] == 4030010
        assert body["errors"][0]["title"] == "Forbidden"
