"""Tests for API token expiration enforcement."""
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from repository.user_repo import user_repo

_ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


class TestTokenExpiration:
    """Expired tokens should be rejected with 401."""

    def test_expired_token_returns_401(self, client: TestClient) -> None:
        """Create a token with a past expiration, verify it is rejected."""
        # Save a token that expired an hour ago
        past = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        user_repo.save_token("expired-test-token-0000000000000", {
            "token": "expired-test-token-0000000000000",
            "userId": "test-user-id",
            "role": "Admin",
            "email": "expired@test.com",
            "expiresAt": past,
        })
        resp = client.get(
            "/web/api/v2.1/agents",
            headers={"Authorization": "ApiToken expired-test-token-0000000000000"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert body["errors"][0]["code"] == 4010011
        assert "expired" in body["errors"][0]["detail"].lower()

    def test_future_token_is_accepted(self, client: TestClient) -> None:
        """A token with a future expiration should work normally."""
        future = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        user_repo.save_token("future-test-token-0000000000000", {
            "token": "future-test-token-0000000000000",
            "userId": "test-user-id",
            "role": "Admin",
            "email": "future@test.com",
            "expiresAt": future,
        })
        resp = client.get(
            "/web/api/v2.1/agents",
            headers={"Authorization": "ApiToken future-test-token-0000000000000"},
        )
        assert resp.status_code == 200

    def test_token_without_expiration_is_accepted(self, client: TestClient) -> None:
        """The preset admin token has no expiresAt and should always work."""
        resp = client.get("/web/api/v2.1/agents", headers=_ADMIN)
        assert resp.status_code == 200
