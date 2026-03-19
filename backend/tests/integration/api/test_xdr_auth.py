"""Integration tests for Cortex XDR HMAC API key authentication.

Verifies HMAC signature validation, role-based access control, and
rejection of invalid/missing credentials.
"""
import hashlib
import hmac
import secrets
import time

from fastapi.testclient import TestClient

XDR_PREFIX = "/xdr/public_api/v1"

# Pre-seeded API keys (from infrastructure/seeders/xdr_auth.py)
ADMIN_KEY_ID = "1"
ADMIN_KEY_SECRET = "xdr-admin-secret"
ANALYST_KEY_ID = "2"
ANALYST_KEY_SECRET = "xdr-analyst-secret"
VIEWER_KEY_ID = "3"
VIEWER_KEY_SECRET = "xdr-viewer-secret"


def _xdr_headers(
    key_id: str = ADMIN_KEY_ID,
    key_secret: str = ADMIN_KEY_SECRET,
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


class TestXdrHmacAuth:
    """Tests for XDR HMAC signature validation."""

    def test_valid_admin_key_returns_200(self, client: TestClient) -> None:
        headers = _xdr_headers(ADMIN_KEY_ID, ADMIN_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_valid_analyst_key_returns_200(self, client: TestClient) -> None:
        headers = _xdr_headers(ANALYST_KEY_ID, ANALYST_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_valid_viewer_key_returns_200(self, client: TestClient) -> None:
        headers = _xdr_headers(VIEWER_KEY_ID, VIEWER_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_invalid_key_id_returns_401(self, client: TestClient) -> None:
        headers = _xdr_headers("999", ADMIN_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 401

    def test_invalid_secret_returns_401(self, client: TestClient) -> None:
        """Wrong secret produces invalid HMAC signature."""
        headers = _xdr_headers(ADMIN_KEY_ID, "wrong-secret")
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 401

    def test_missing_all_headers_returns_401(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
        )
        assert resp.status_code == 401

    def test_missing_auth_id_header_returns_401(self, client: TestClient) -> None:
        headers = _xdr_headers()
        del headers["x-xdr-auth-id"]
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 401

    def test_missing_nonce_header_returns_401(self, client: TestClient) -> None:
        headers = _xdr_headers()
        del headers["x-xdr-nonce"]
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 401

    def test_missing_timestamp_header_returns_401(self, client: TestClient) -> None:
        headers = _xdr_headers()
        del headers["x-xdr-timestamp"]
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 401

    def test_tampered_signature_returns_401(self, client: TestClient) -> None:
        """Modifying the Authorization hash after construction should fail."""
        headers = _xdr_headers()
        headers["Authorization"] = "a" * 64  # wrong hash
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 401


class TestXdrRbac:
    """Tests for XDR role-based access control."""

    def test_viewer_can_read_incidents(self, client: TestClient) -> None:
        headers = _xdr_headers(VIEWER_KEY_ID, VIEWER_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_viewer_cannot_update_incident(self, client: TestClient) -> None:
        """Viewer role should receive 403 on mutation endpoints."""
        headers = _xdr_headers(VIEWER_KEY_ID, VIEWER_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/update_incident/",
            json={"request_data": {"incident_id": "inc-001", "update_data": {"status": "resolved_true_positive"}}},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_viewer_cannot_isolate_endpoint(self, client: TestClient) -> None:
        headers = _xdr_headers(VIEWER_KEY_ID, VIEWER_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": "mock-endpoint-001"}},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_viewer_cannot_insert_alerts(self, client: TestClient) -> None:
        headers = _xdr_headers(VIEWER_KEY_ID, VIEWER_KEY_SECRET)
        resp = client.post(
            f"{XDR_PREFIX}/alerts/insert_parsed_alerts/",
            json={"request_data": {"alerts": [{"severity": "high"}]}},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_analyst_can_update_incident(self, client: TestClient) -> None:
        """Analyst role should be allowed write access."""
        # Get a real incident ID first
        admin_headers = _xdr_headers(ADMIN_KEY_ID, ADMIN_KEY_SECRET)
        list_resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=admin_headers,
        )
        incidents = list_resp.json()["reply"]["incidents"]
        if incidents:
            incident_id = incidents[0]["incident_id"]
            headers = _xdr_headers(ANALYST_KEY_ID, ANALYST_KEY_SECRET)
            resp = client.post(
                f"{XDR_PREFIX}/incidents/update_incident/",
                json={"request_data": {"incident_id": incident_id, "update_data": {"status": "under_investigation"}}},
                headers=headers,
            )
            assert resp.status_code == 200
