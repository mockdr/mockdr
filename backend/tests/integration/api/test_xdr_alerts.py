"""Integration tests for Cortex XDR Alerts endpoints.

Verifies alert listing, filtering, original alert retrieval,
alert insertion (parsed and CEF), and alert updates.
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


class TestGetAlerts:
    """Tests for POST /alerts/get_alerts_by_filter_data/."""

    def test_get_alerts_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_response_has_reply_envelope(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        body = resp.json()
        assert "reply" in body
        reply = body["reply"]
        assert "total_count" in reply
        assert "result_count" in reply
        assert "alerts" in reply

    def test_alerts_have_expected_fields(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        alerts = resp.json()["reply"]["alerts"]
        assert len(alerts) > 0
        alert = alerts[0]
        required_fields = [
            "alert_id", "severity", "description", "source",
            "detection_timestamp", "endpoint_id", "host_name",
            "alert_action_status",
        ]
        for field in required_fields:
            assert field in alert, f"Required field '{field}' missing from alert"

    def test_filter_by_severity(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {
                "filters": [{"field": "severity", "value": ["high"]}],
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        alerts = resp.json()["reply"]["alerts"]
        for alert in alerts:
            assert alert["severity"] == "high"

    def test_pagination(self, client: TestClient) -> None:
        headers = _xdr_headers()
        r1 = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {"search_from": 0, "search_to": 2}},
            headers=headers,
        )
        r2 = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {"search_from": 2, "search_to": 4}},
            headers=headers,
        )
        ids1 = {a["alert_id"] for a in r1.json()["reply"]["alerts"]}
        ids2 = {a["alert_id"] for a in r2.json()["reply"]["alerts"]}
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"


class TestGetOriginalAlerts:
    """Tests for POST /alerts/get_original_alerts/."""

    def _get_alert_ids(self, client: TestClient, count: int = 2) -> list[str]:
        """Return the first N alert IDs."""
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {"search_from": 0, "search_to": count}},
            headers=_xdr_headers(),
        )
        return [a["alert_id"] for a in resp.json()["reply"]["alerts"]]

    def test_get_original_alerts_by_id_list(self, client: TestClient) -> None:
        alert_ids = self._get_alert_ids(client)
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_original_alerts/",
            json={"request_data": {"alert_id_list": alert_ids}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        returned = resp.json()["reply"]["alerts"]
        returned_ids = {a["alert_id"] for a in returned}
        assert set(alert_ids) == returned_ids

    def test_nonexistent_alert_returns_empty(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_original_alerts/",
            json={"request_data": {"alert_id_list": ["nonexistent-alert-id"]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"]["alerts"] == []


class TestInsertAlerts:
    """Tests for POST /alerts/insert_parsed_alerts/ and insert_cef_alerts/."""

    def test_insert_parsed_alerts(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/insert_parsed_alerts/",
            json={"request_data": {"alerts": [
                {
                    "product": "Test Product",
                    "alert_name": "Suspicious activity detected",
                    "severity": "high",
                    "host_name": "ACME-TEST-001",
                    "host_ip": ["10.10.1.200"],
                    "user_name": "testuser",
                },
            ]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

    def test_insert_cef_alerts(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/insert_cef_alerts/",
            json={"request_data": {"alerts": [
                {
                    "name": "CEF Test Alert",
                    "severity": "medium",
                    "device_host_name": "ACME-TEST-002",
                    "cef_version": "0",
                },
            ]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True


class TestUpdateAlerts:
    """Tests for POST /alerts/update_alerts."""

    def _get_first_alert_id(self, client: TestClient) -> str:
        resp = client.post(
            f"{XDR_PREFIX}/alerts/get_alerts_by_filter_data/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        return resp.json()["reply"]["alerts"][0]["alert_id"]

    def test_update_alert_status(self, client: TestClient) -> None:
        alert_id = self._get_first_alert_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/alerts/update_alerts",
            json={"request_data": {
                "alert_id_list": [alert_id],
                "update_data": {"status": "resolved"},
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

    def test_update_alert_severity(self, client: TestClient) -> None:
        alert_id = self._get_first_alert_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/alerts/update_alerts",
            json={"request_data": {
                "alert_id_list": [alert_id],
                "update_data": {"severity": "critical"},
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

        # Verify severity persisted
        get_resp = client.post(
            f"{XDR_PREFIX}/alerts/get_original_alerts/",
            json={"request_data": {"alert_id_list": [alert_id]}},
            headers=_xdr_headers(),
        )
        alert = get_resp.json()["reply"]["alerts"][0]
        assert alert["severity"] == "critical"
