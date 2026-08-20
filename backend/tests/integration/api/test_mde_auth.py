"""Integration tests for Microsoft Defender for Endpoint OAuth2 authentication.

Verifies the Azure AD client credentials flow, token validation,
role-based access control, and response structure match the real MDE API.
"""
import pytest
from fastapi.testclient import TestClient

MOCK_TENANT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

_ADMIN_CREDENTIALS = {
    "client_id": "mde-mock-admin-client",
    "client_secret": "mde-mock-admin-secret",
    "grant_type": "client_credentials",
}


class TestMdeTenantScopedTokenUrl:
    """The token endpoint accepts real Entra's tenant-scoped URL shape."""

    def test_tenant_scoped_url_returns_token(self, client: TestClient) -> None:
        """The tenant-scoped URL real Entra uses should issue a token."""
        resp = client.post(
            f"/mde/{MOCK_TENANT_ID}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 200
        assert resp.json()["token_type"] == "Bearer"

    def test_tenant_scoped_token_is_usable(self, client: TestClient) -> None:
        """A token from the tenant-scoped URL authenticates MDE calls."""
        resp = client.post(
            f"/mde/{MOCK_TENANT_ID}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        assert client.get("/mde/api/machines", headers=headers).status_code == 200

    def test_verified_domain_is_accepted(self, client: TestClient) -> None:
        """Entra accepts a verified domain name in place of the tenant GUID."""
        resp = client.post(
            "/mde/acmecorp.onmicrosoft.com/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 200

    def test_unknown_tenant_returns_400(self, client: TestClient) -> None:
        """A tenant this mock does not host should be rejected, not served."""
        resp = client.post(
            "/mde/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
            data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 400

    @pytest.mark.parametrize("alias", ["common", "organizations", "consumers"])
    def test_multi_tenant_aliases_are_rejected(
        self, client: TestClient, alias: str,
    ) -> None:
        """Entra rejects the multi-tenant authorities for client credentials."""
        resp = client.post(
            f"/mde/{alias}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 400


def _mde_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return MDE Bearer headers."""
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestMdeTokenEndpoint:
    """Tests for POST /mde/oauth2/v2.0/token."""

    def test_valid_credentials_return_200(self, client: TestClient) -> None:
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        })
        assert resp.status_code == 200

    def test_valid_credentials_return_access_token(self, client: TestClient) -> None:
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        })
        body = resp.json()
        assert "access_token" in body
        assert isinstance(body["access_token"], str)
        assert len(body["access_token"]) > 0

    def test_token_response_has_correct_fields(self, client: TestClient) -> None:
        """Token response must include access_token, token_type, expires_in, ext_expires_in."""
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        })
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3599
        assert body["ext_expires_in"] == 3599
        assert "access_token" in body

    def test_invalid_client_id_returns_401(self, client: TestClient) -> None:
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "wrong-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        })
        assert resp.status_code == 401

    def test_invalid_client_secret_returns_401(self, client: TestClient) -> None:
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "wrong-secret",
            "grant_type": "client_credentials",
        })
        assert resp.status_code == 401

    def test_invalid_grant_type_returns_400(self, client: TestClient) -> None:
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "authorization_code",
        })
        assert resp.status_code == 400

    def test_token_can_access_machines(self, client: TestClient) -> None:
        """Token obtained from OAuth endpoint should grant access to /mde/api/machines."""
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines", headers=headers)
        assert resp.status_code == 200


class TestMdeBearerAuth:
    """Tests for Bearer token validation on protected endpoints."""

    def test_valid_token_on_protected_endpoint(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machines", headers=headers)
        assert resp.status_code == 200

    def test_invalid_bearer_token_returns_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer totally-invalid-token"}
        resp = client.get("/mde/api/machines", headers=headers)
        assert resp.status_code == 401

    def test_missing_auth_header_returns_401(self, client: TestClient) -> None:
        resp = client.get("/mde/api/machines")
        assert resp.status_code == 401

    def test_malformed_auth_header_returns_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Token some-value"}
        resp = client.get("/mde/api/machines", headers=headers)
        assert resp.status_code == 401


class TestMdeRbac:
    """Tests for MDE role-based access control."""

    def test_viewer_can_read(self, client: TestClient) -> None:
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-viewer-client",
            "client_secret": "mde-mock-viewer-secret",
            "grant_type": "client_credentials",
        })
        headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        resp = client.get("/mde/api/machines", headers=headers)
        assert resp.status_code == 200

    def test_viewer_cannot_write(self, client: TestClient) -> None:
        """Viewer role should receive 403 on mutation endpoints."""
        resp = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-viewer-client",
            "client_secret": "mde-mock-viewer-secret",
            "grant_type": "client_credentials",
        })
        viewer_headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

        # Get a machine ID using admin
        admin_headers = _mde_auth(client)
        machines_resp = client.get("/mde/api/machines", headers=admin_headers)
        machine_id = machines_resp.json()["value"][0]["id"]

        resp = client.post(
            f"/mde/api/machines/{machine_id}/isolate",
            headers=viewer_headers,
            json={"Comment": "test isolation", "IsolationType": "Full"},
        )
        assert resp.status_code == 403


class TestMdeODataCount:
    """MDE supports $count=true on its list endpoints."""

    def _headers(self, client: TestClient) -> dict[str, str]:
        resp = client.post("/mde/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS)
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    def test_count_returns_odata_count(self, client: TestClient) -> None:
        resp = client.get("/mde/api/machines?$count=true", headers=self._headers(client))
        assert resp.status_code == 200
        assert resp.json()["@odata.count"] > 0

    def test_count_is_the_total_not_the_page(self, client: TestClient) -> None:
        """$count reports matches, not how many fit on this page."""
        headers = self._headers(client)
        body = client.get("/mde/api/machines?$count=true&$top=2", headers=headers).json()
        assert len(body["value"]) == 2
        assert body["@odata.count"] > 2

    def test_count_omitted_when_not_requested(self, client: TestClient) -> None:
        body = client.get("/mde/api/machines", headers=self._headers(client)).json()
        assert "@odata.count" not in body

    def test_alerts_support_count(self, client: TestClient) -> None:
        resp = client.get("/mde/api/alerts?$count=true", headers=self._headers(client))
        assert resp.json()["@odata.count"] > 0
