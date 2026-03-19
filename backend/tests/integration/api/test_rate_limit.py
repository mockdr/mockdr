"""Integration tests for the rate-limit simulation middleware.

GET  /_dev/rate-limit  — get current config
POST /_dev/rate-limit  — update config
"""
import pytest
from fastapi.testclient import TestClient

from api.middleware.rate_limit import reset_counters, set_config


@pytest.fixture(autouse=True)
def reset_rate_limit() -> None:
    """Reset rate-limit config to disabled state after each test."""
    yield
    set_config(enabled=False, rpm=60)
    reset_counters()


class TestRateLimitConfig:
    """Tests for GET/POST /_dev/rate-limit."""

    def test_get_returns_disabled_by_default(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get("/web/api/v2.1/_dev/rate-limit", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert "requestsPerMinute" in body

    def test_post_enables_rate_limit(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            "/web/api/v2.1/_dev/rate-limit",
            headers=auth_headers,
            json={"enabled": True, "requestsPerMinute": 10},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is True
        assert body["requestsPerMinute"] == 10

    def test_get_reflects_updated_config(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        client.post(
            "/web/api/v2.1/_dev/rate-limit",
            headers=auth_headers,
            json={"enabled": True, "requestsPerMinute": 5},
        )
        resp = client.get("/web/api/v2.1/_dev/rate-limit", headers=auth_headers)
        assert resp.json()["enabled"] is True
        assert resp.json()["requestsPerMinute"] == 5


class TestRateLimiting:
    """Tests that the rate limit middleware enforces limits correctly."""

    def test_third_request_returns_429_when_limit_is_2(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        # Enable rate limit with limit=2
        set_config(enabled=True, rpm=2)
        reset_counters()

        resp1 = client.get("/web/api/v2.1/agents", headers=auth_headers)
        resp2 = client.get("/web/api/v2.1/agents", headers=auth_headers)
        resp3 = client.get("/web/api/v2.1/agents", headers=auth_headers)

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp3.status_code == 429

    def test_429_response_has_s1_error_format(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        set_config(enabled=True, rpm=1)
        reset_counters()

        client.get("/web/api/v2.1/agents", headers=auth_headers)
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers)

        assert resp.status_code == 429
        body = resp.json()
        assert "errors" in body
        assert body["data"] is None
        errors = body["errors"]
        assert len(errors) >= 1
        assert errors[0]["code"] == 4290001
        assert errors[0]["title"] == "Too Many Requests"

    def test_dev_paths_exempt_from_rate_limit(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        set_config(enabled=True, rpm=1)
        reset_counters()

        # These /_dev/ paths should never be rate-limited
        for _ in range(5):
            resp = client.get("/web/api/v2.1/_dev/stats", headers=auth_headers)
            assert resp.status_code == 200, "/_dev/ path should be exempt from rate limiting"

    def test_disabling_rate_limit_allows_requests(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        # Enable with very low limit
        set_config(enabled=True, rpm=1)
        reset_counters()
        client.get("/web/api/v2.1/agents", headers=auth_headers)

        # Should be rate limited
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers)
        assert resp.status_code == 429

        # Disable and counters should be reset
        set_config(enabled=False, rpm=60)
        reset_counters()

        resp = client.get("/web/api/v2.1/agents", headers=auth_headers)
        assert resp.status_code == 200
