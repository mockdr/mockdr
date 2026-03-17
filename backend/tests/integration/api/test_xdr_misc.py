"""Integration tests for miscellaneous Cortex XDR endpoints.

Covers healthcheck, tenant info, XQL queries, RBAC users/roles,
audit logs, distributions, scripts, and IOC management.
"""
import hashlib
import hmac
import secrets
import time

from fastapi.testclient import TestClient

XDR_PREFIX = "/xdr/public_api/v1"


def _xdr_headers(
    key_id: str = "1",
    key_secret: str = "xdr-admin-secret",
) -> dict[str, str]:
    """Build valid XDR HMAC auth headers."""
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    # HMAC-SHA256: key_secret as HMAC key, nonce:timestamp as message
    auth_hash = hmac.new(key_secret.encode(), (nonce + ":" + timestamp).encode(), hashlib.sha256).hexdigest()
    return {
        "x-xdr-auth-id": key_id,
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": auth_hash,
    }


class TestHealthcheck:
    """Tests for GET /healthcheck."""

    def test_healthcheck_returns_200(self, client: TestClient) -> None:
        resp = client.get(f"{XDR_PREFIX}/healthcheck")
        assert resp.status_code == 200

    def test_healthcheck_no_auth_required(self, client: TestClient) -> None:
        """Healthcheck should work without any auth headers."""
        resp = client.get(f"{XDR_PREFIX}/healthcheck")
        assert resp.status_code == 200


class TestTenantInfo:
    """Tests for POST /system/get_tenant_info/."""

    def test_get_tenant_info_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/system/get_tenant_info/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_tenant_info_has_reply_envelope(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/system/get_tenant_info/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        body = resp.json()
        assert "reply" in body


class TestXqlQueries:
    """Tests for POST /xql/start_xql_query and /xql/get_query_results."""

    def test_start_xql_query(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/xql/start_xql_query",
            json={"request_data": {"query": "dataset = xdr_data | limit 10"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert isinstance(reply, (str, dict))

    def test_xql_query_lifecycle(self, client: TestClient) -> None:
        """Start a query, then retrieve its results."""
        headers = _xdr_headers()

        # Start query
        start_resp = client.post(
            f"{XDR_PREFIX}/xql/start_xql_query",
            json={"request_data": {"query": "dataset = xdr_data | limit 5"}},
            headers=headers,
        )
        assert start_resp.status_code == 200
        # Extract query_id from reply (may be string or dict with query_id key)
        reply = start_resp.json()["reply"]
        if isinstance(reply, dict):
            query_id = reply.get("query_id", reply.get("execution_id", ""))
        else:
            query_id = str(reply)

        # Get results
        results_resp = client.post(
            f"{XDR_PREFIX}/xql/get_query_results",
            json={"request_data": {"query_id": query_id}},
            headers=headers,
        )
        assert results_resp.status_code == 200
        assert "reply" in results_resp.json()

    def test_get_xql_quota(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/xql/get_quota",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()


class TestRbacEndpoints:
    """Tests for RBAC user and role listing."""

    def test_get_users_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/rbac/get_users/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()

    def test_get_user_groups_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/rbac/get_user_group/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()

    def test_get_roles_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/rbac/get_roles/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()


class TestAuditLogs:
    """Tests for POST /audits/management_logs/."""

    def test_get_management_logs_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/audits/management_logs/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()

    def test_get_agent_reports_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/audits/agents_reports/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()


class TestDistributions:
    """Tests for POST /distributions/get_versions/."""

    def test_get_versions_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/distributions/get_versions/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()


class TestScripts:
    """Tests for POST /scripts/get_scripts/."""

    def test_get_scripts_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/scripts/get_scripts/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "reply" in resp.json()

    def test_scripts_list_has_data(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/scripts/get_scripts/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        # Reply may be a list or have a "scripts" key
        if isinstance(reply, dict):
            assert "total_count" in reply
        else:
            assert isinstance(reply, list)


class TestIocs:
    """Tests for IOC indicator management."""

    def test_insert_iocs(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/indicators/tim_insert_jsons/",
            json={"request_data": {"indicators": [
                {
                    "indicator": "evil-domain.com",
                    "type": "domain_name",
                    "severity": "high",
                    "comment": "Test IOC from integration test",
                },
            ]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is not None

    def test_viewer_cannot_insert_iocs(self, client: TestClient) -> None:
        headers = _xdr_headers("3", "xdr-viewer-secret")
        resp = client.post(
            f"{XDR_PREFIX}/indicators/tim_insert_jsons/",
            json={"request_data": {"indicators": [
                {"indicator": "test.com", "type": "domain_name", "severity": "low"},
            ]}},
            headers=headers,
        )
        assert resp.status_code == 403


class TestTags:
    """Tests for XDR tag assignment endpoints."""

    def test_assign_tag(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/tags/agents/assign/",
            json={"request_data": {
                "endpoint_ids": ["mock-endpoint-001"],
                "tag": "VIP",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert reply["assigned_count"] == 1
        assert reply["tag"] == "VIP"

    def test_remove_tag(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/tags/agents/remove/",
            json={"request_data": {
                "endpoint_ids": ["mock-endpoint-001"],
                "tag": "VIP",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert reply["removed_count"] == 1


class TestAlertExclusions:
    """Tests for alert exclusion endpoints."""

    def test_list_exclusions(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts_exclusion/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert "total_count" in reply

    def test_add_exclusion(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts_exclusion/add/",
            json={"request_data": {
                "name": "Test Exclusion",
                "description": "Exclude benign alerts",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert "exclusion_id" in reply
        assert reply["name"] == "Test Exclusion"

    def test_delete_exclusion(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts_exclusion/delete/",
            json={"request_data": {"exclusion_id": "excl-001"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True


class TestDeviceControl:
    """Tests for device control violation listing."""

    def test_get_violations(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/device_control/get_violations/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert "total_count" in reply


class TestQuarantineStatus:
    """Tests for quarantine status listing."""

    def test_get_quarantine_status(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/quarantine/status/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        reply = resp.json()["reply"]
        assert "total_count" in reply
