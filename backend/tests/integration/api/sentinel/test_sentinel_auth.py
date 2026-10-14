"""Integration tests for Sentinel OAuth2 authentication."""
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"


def _get_token(client: TestClient) -> str:
    """Get a valid Sentinel OAuth2 token."""
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestATokenIsForOneResource:
    """A token's audience is the resource its scope asked for, and each API checks it.

    Azure Resource Manager refuses a token issued for another resource with
    `InvalidAuthenticationTokenAudience` — "The access token has been
    obtained for wrong audience or resource …" (401 from ARM, as Microsoft
    Q&A threads record it); the Azure Monitor "Logs query timeouts and
    errors" page lists the same code as a 403. The mock accepted any token
    on either API, so a client that asked for the wrong scope passed here.
    """

    _WS = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg"
        "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
        "/providers/Microsoft.SecurityInsights"
    )

    def _token(self, client: TestClient, scope: str) -> dict[str, str]:
        resp = client.post(f"{SENTINEL_PREFIX}/oauth2/v2.0/token", data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
            "scope": scope,
        })
        assert resp.status_code == 200
        return _bearer(resp.json()["access_token"])

    def _arm(self, client: TestClient, headers: dict) -> object:
        return client.get(f"{SENTINEL_PREFIX}{self._WS}/incidents", headers=headers)

    def _la(self, client: TestClient, headers: dict) -> object:
        return client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityIncident | take 1"}, headers=headers,
        )

    def test_each_api_takes_its_own_token(self, client: TestClient) -> None:
        assert self._arm(client, self._token(
            client, "https://management.azure.com/.default")).status_code == 200
        assert self._arm(client, self._token(
            client, "https://management.core.windows.net/.default")).status_code == 200
        assert self._la(client, self._token(
            client, "https://api.loganalytics.io/.default")).status_code == 200

    def test_arm_refuses_a_log_analytics_token(self, client: TestClient) -> None:
        resp = self._arm(client, self._token(client, "https://api.loganalytics.io/.default"))
        assert resp.status_code == 401
        error = resp.json()["error"]
        assert error["code"] == "InvalidAuthenticationTokenAudience"
        assert "https://api.loganalytics.io" in error["message"]
        assert "https://management.azure.com/" in error["message"]

    def test_log_analytics_refuses_an_arm_token(self, client: TestClient) -> None:
        resp = self._la(client, self._token(client, "https://management.azure.com/.default"))
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "InvalidAuthenticationTokenAudience"

    def test_a_graph_token_is_good_for_neither(self, client: TestClient) -> None:
        graph = self._token(client, "https://graph.microsoft.com/.default")
        assert self._arm(client, graph).status_code == 401
        assert self._la(client, graph).status_code == 403


class TestTenantScopedTokenUrl:
    """The token endpoint accepts real Entra's tenant-scoped URL shape."""

    _CREDENTIALS = {
        "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
    }

    def test_tenant_scoped_url_returns_token(self, client: TestClient) -> None:
        """The tenant-scoped URL real Entra uses should issue a token."""
        resp = client.post(
            f"{SENTINEL_PREFIX}/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/token",
            data=self._CREDENTIALS,
        )
        assert resp.status_code == 200
        assert resp.json()["token_type"] == "Bearer"

    def test_verified_domain_is_accepted(self, client: TestClient) -> None:
        """Entra accepts a verified domain name in place of the tenant GUID."""
        resp = client.post(
            f"{SENTINEL_PREFIX}/acmecorp.onmicrosoft.com/oauth2/v2.0/token",
            data=self._CREDENTIALS,
        )
        assert resp.status_code == 200

    def test_unknown_tenant_returns_400(self, client: TestClient) -> None:
        """A tenant this mock does not host should be rejected, not served."""
        resp = client.post(
            f"{SENTINEL_PREFIX}/contoso.onmicrosoft.com/oauth2/v2.0/token",
            data=self._CREDENTIALS,
        )
        assert resp.status_code == 400

    def test_multi_tenant_alias_is_rejected(self, client: TestClient) -> None:
        """Entra rejects the multi-tenant authorities for client credentials."""
        resp = client.post(
            f"{SENTINEL_PREFIX}/common/oauth2/v2.0/token", data=self._CREDENTIALS,
        )
        assert resp.status_code == 400


class TestOAuth2TokenExchange:
    """Tests for POST /sentinel/oauth2/v2.0/token."""

    def test_valid_credentials(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
            data={
                "client_id": "sentinel-mock-client-id",
                "client_secret": "sentinel-mock-client-secret",
                "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] > 0

    def test_invalid_credentials(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
            data={
                "client_id": "wrong",
                "client_secret": "wrong",
                "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
            },
        )
        assert resp.status_code == 401

    def test_bearer_token_works(self, client: TestClient) -> None:
        _get_token(client)
        resp = client.get(
            f"{SENTINEL_PREFIX}/providers/Microsoft.SecurityInsights/operations",
        )
        assert resp.status_code == 200
