"""Tests for security headers middleware."""
from fastapi.testclient import TestClient

_ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


class TestSecurityHeaders:
    """Every response should include standard security headers."""

    def test_x_content_type_options(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=_ADMIN)
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=_ADMIN)
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=_ADMIN)
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=_ADMIN)
        assert "camera=()" in resp.headers.get("permissions-policy", "")

    def test_headers_present_on_error_responses(self, client: TestClient) -> None:
        """Security headers should also be present on 401 responses."""
        resp = client.get("/web/api/v2.1/agents")
        assert resp.status_code == 401
        assert resp.headers.get("x-content-type-options") == "nosniff"


class TestErrorResponseEnvelope:
    """All HTTP error responses should use the S1 error envelope."""

    def test_401_has_s1_envelope(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents")
        body = resp.json()
        assert "errors" in body
        assert body["data"] is None

    def test_404_has_s1_envelope(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents/nonexistent-id", headers=_ADMIN)
        body = resp.json()
        assert "errors" in body
        assert body["data"] is None

    def test_403_has_s1_envelope(self, client: TestClient) -> None:
        viewer = {"Authorization": "ApiToken viewer-token-0000-0000-000000000002"}
        resp = client.post("/web/api/v2.1/sites", headers=viewer,
                           json={"data": {"name": "X"}})
        body = resp.json()
        assert resp.status_code == 403
        assert "errors" in body
        assert body["data"] is None
