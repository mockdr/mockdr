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
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestOAuth2TokenExchange:
    """Tests for POST /sentinel/oauth2/v2.0/token."""

    def test_valid_credentials(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
            data={
                "client_id": "sentinel-mock-client-id",
                "client_secret": "sentinel-mock-client-secret",
                "grant_type": "client_credentials",
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
            },
        )
        assert resp.status_code == 401

    def test_bearer_token_works(self, client: TestClient) -> None:
        _get_token(client)
        resp = client.get(
            f"{SENTINEL_PREFIX}/providers/Microsoft.SecurityInsights/operations",
        )
        assert resp.status_code == 200
