"""Integration tests for Graph API OAuth2 authentication."""
import pytest
from fastapi.testclient import TestClient

MOCK_TENANT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

_ADMIN_CREDENTIALS = {
    "client_id": "graph-mock-admin-client",
    "client_secret": "graph-mock-admin-secret",
    "grant_type": "client_credentials",
}


class TestGraphAuth:
    """Graph OAuth2 token endpoint tests."""

    def test_valid_credentials_return_token(self, client: TestClient) -> None:
        """Valid client credentials should return an access token."""
        resp = client.post(
            "/graph/oauth2/v2.0/token",
            data={
                "client_id": "graph-mock-admin-client",
                "client_secret": "graph-mock-admin-secret",
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3599
        assert "access_token" in body
        assert len(body["access_token"]) > 0

    def test_invalid_secret_returns_401(self, client: TestClient) -> None:
        """Wrong client_secret should return 401."""
        resp = client.post(
            "/graph/oauth2/v2.0/token",
            data={
                "client_id": "graph-mock-admin-client",
                "client_secret": "wrong-secret",
                "grant_type": "client_credentials",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "invalid_client"

    def test_invalid_client_id_returns_401(self, client: TestClient) -> None:
        """Unknown client_id should return 401."""
        resp = client.post(
            "/graph/oauth2/v2.0/token",
            data={
                "client_id": "nonexistent-client",
                "client_secret": "any-secret",
                "grant_type": "client_credentials",
            },
        )
        assert resp.status_code == 401

    def test_invalid_grant_type_returns_400(self, client: TestClient) -> None:
        """Invalid grant_type should return 400."""
        resp = client.post(
            "/graph/oauth2/v2.0/token",
            data={
                "client_id": "graph-mock-admin-client",
                "client_secret": "graph-mock-admin-secret",
                "grant_type": "authorization_code",
            },
        )
        assert resp.status_code == 400

    def test_token_carries_plan_and_licenses(self, client: TestClient) -> None:
        """Token record should carry plan and licenses from the client."""
        resp = client.post(
            "/graph/oauth2/v2.0/token",
            data={
                "client_id": "graph-mock-smb-client",
                "client_secret": "graph-mock-smb-secret",
                "grant_type": "client_credentials",
            },
        )
        assert resp.status_code == 200
        token = resp.json()["access_token"]

        # Use the token to access an endpoint — it should work
        headers = {"Authorization": f"Bearer {token}"}
        org_resp = client.get("/graph/v1.0/organization", headers=headers)
        assert org_resp.status_code == 200

    def test_missing_auth_header_returns_401(self, client: TestClient) -> None:
        """Requests without Authorization header should get 401."""
        resp = client.get("/graph/v1.0/organization")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "InvalidAuthenticationToken"

    def test_invalid_bearer_token_returns_401(self, client: TestClient) -> None:
        """Requests with an invalid Bearer token should get 401."""
        resp = client.get(
            "/graph/v1.0/organization",
            headers={"Authorization": "Bearer invalid-token-xyz"},
        )
        assert resp.status_code == 401


class TestGraphTenantScopedTokenUrl:
    """The token endpoint accepts real Entra's tenant-scoped URL shape."""

    def test_tenant_scoped_url_returns_token(self, client: TestClient) -> None:
        """The tenant-scoped URL real Entra uses should issue a token."""
        resp = client.post(
            f"/graph/{MOCK_TENANT_ID}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 200
        assert resp.json()["token_type"] == "Bearer"

    def test_tenant_scoped_token_is_usable(self, client: TestClient) -> None:
        """A token from the tenant-scoped URL authenticates Graph calls."""
        resp = client.post(
            f"/graph/{MOCK_TENANT_ID}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        assert client.get("/graph/v1.0/organization", headers=headers).status_code == 200

    def test_tenant_segment_is_case_insensitive(self, client: TestClient) -> None:
        """Entra treats tenant GUIDs case-insensitively."""
        resp = client.post(
            f"/graph/{MOCK_TENANT_ID.upper()}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 200

    def test_unknown_tenant_returns_400(self, client: TestClient) -> None:
        """A tenant this mock does not host should be rejected, not served."""
        resp = client.post(
            "/graph/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
            data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["code"] == "invalid_request"
        assert "AADSTS90002" in error["message"]

    @pytest.mark.parametrize("alias", ["common", "organizations", "consumers"])
    def test_multi_tenant_aliases_are_rejected(
        self, client: TestClient, alias: str,
    ) -> None:
        """Entra rejects the multi-tenant authorities for client credentials."""
        resp = client.post(
            f"/graph/{alias}/oauth2/v2.0/token", data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 400

    def test_unknown_tenant_accepted_when_strict_disabled(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """MOCKDR_STRICT_TENANT=false lets any concrete tenant through."""
        monkeypatch.setattr("utils.entra_tenant.STRICT_TENANT", False)
        resp = client.post(
            "/graph/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
            data=_ADMIN_CREDENTIALS,
        )
        assert resp.status_code == 200

    def test_invalid_credentials_still_401_on_tenant_url(
        self, client: TestClient,
    ) -> None:
        """A bad secret outranks nothing — it is still a 401 on the scoped URL."""
        resp = client.post(
            f"/graph/{MOCK_TENANT_ID}/oauth2/v2.0/token",
            data={**_ADMIN_CREDENTIALS, "client_secret": "wrong-secret"},
        )
        assert resp.status_code == 401


class TestGraphOrganization:
    """Graph Organization endpoint tests."""

    def test_list_organization_returns_odata(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/organization should return OData envelope with one org."""
        resp = client.get("/graph/v1.0/organization", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 1
        org = body["value"][0]
        assert org["displayName"] == "AcmeCorp"
        assert org["tenantType"] == "AAD"
        assert len(org["verifiedDomains"]) >= 1
        assert org["verifiedDomains"][0]["name"] == "acmecorp.onmicrosoft.com"

    def test_all_plan_levels_can_access_organization(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Organization should be accessible from any plan level."""
        resp = client.get("/graph/v1.0/organization", headers=graph_p1_headers)
        assert resp.status_code == 200
        assert len(resp.json()["value"]) == 1
