"""Integration tests for CrowdStrike OAuth2 authentication endpoints.

Verifies the client credentials flow, token validation, role-based access
control, and response structure match the real CrowdStrike Falcon API.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _cs_viewer_auth(client: TestClient) -> dict[str, str]:
    """Authenticate as viewer and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-viewer-client",
        "client_secret": "cs-mock-viewer-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestCsTokenEndpoint:
    """Tests for POST /cs/oauth2/token."""

    def test_valid_credentials_return_200(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        })
        assert resp.status_code == 200

    def test_valid_credentials_return_access_token(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        })
        body = resp.json()
        assert "access_token" in body
        assert isinstance(body["access_token"], str)
        assert len(body["access_token"]) > 0

    def test_token_response_has_correct_fields(self, client: TestClient) -> None:
        """Token response must include access_token, token_type, and expires_in."""
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        })
        body = resp.json()
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 1799
        assert "access_token" in body

    def test_invalid_credentials_return_401(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "wrong-client",
            "client_secret": "wrong-secret",
        })
        assert resp.status_code == 401

    def test_invalid_secret_return_401(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "wrong-secret",
        })
        assert resp.status_code == 401

    def test_missing_form_fields_return_422(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={})
        assert resp.status_code == 422

    def test_missing_client_secret_return_422(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
        })
        assert resp.status_code == 422

    def test_viewer_credentials_return_200(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-viewer-client",
            "client_secret": "cs-mock-viewer-secret",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_analyst_credentials_return_200(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-analyst-client",
            "client_secret": "cs-mock-analyst-secret",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()


class TestCsBearerAuth:
    """Tests for Bearer token validation on protected endpoints."""

    def test_valid_token_on_protected_endpoint(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers)
        assert resp.status_code == 200

    def test_invalid_bearer_token_return_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer totally-invalid-token"}
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers)
        assert resp.status_code == 401

    def test_missing_auth_header_return_401(self, client: TestClient) -> None:
        resp = client.get("/cs/devices/queries/devices/v1")
        assert resp.status_code == 401

    def test_malformed_auth_header_return_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Token some-value"}
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers)
        assert resp.status_code == 401


class TestCsRbac:
    """Tests for CrowdStrike role-based access control."""

    def test_viewer_can_read(self, client: TestClient) -> None:
        headers = _cs_viewer_auth(client)
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers)
        assert resp.status_code == 200

    def test_viewer_cannot_write(self, client: TestClient) -> None:
        """Viewer role should receive 403 on mutation endpoints."""
        headers = _cs_viewer_auth(client)
        # Get a host ID first to use in the action
        admin_headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=admin_headers,
            params={"limit": 1},
        )
        host_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "contain"},
            json={"ids": [host_id]},
        )
        assert resp.status_code == 403

    def test_viewer_cannot_create_ioc(self, client: TestClient) -> None:
        headers = _cs_viewer_auth(client)
        resp = client.post(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            json={"indicators": [{"type": "domain", "value": "evil.com", "action": "detect"}]},
        )
        assert resp.status_code == 403
