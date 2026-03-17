"""Integration tests for API authentication.

Verifies that every endpoint requires a valid ApiToken header and that
invalid/missing tokens are correctly rejected.
"""
from fastapi.testclient import TestClient

_GUARDED_ENDPOINTS = [
    ("GET", "/web/api/v2.1/agents"),
    ("GET", "/web/api/v2.1/threats"),
    ("GET", "/web/api/v2.1/sites"),
    ("GET", "/web/api/v2.1/groups"),
    ("GET", "/web/api/v2.1/exclusions"),
    ("GET", "/web/api/v2.1/users"),
    ("GET", "/web/api/v2.1/firewall-control"),
    ("GET", "/web/api/v2.1/activities"),
]


class TestAuthRequired:
    def test_no_header_returns_401(self, client: TestClient) -> None:
        for method, path in _GUARDED_ENDPOINTS:
            resp = client.request(method, path)
            assert resp.status_code == 401, f"{method} {path} should require auth"

    def test_wrong_scheme_returns_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer admin-token-0000-0000-000000000001"}
        for method, path in _GUARDED_ENDPOINTS:
            resp = client.request(method, path, headers=headers)
            assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client: TestClient) -> None:
        headers = {"Authorization": "ApiToken not-a-real-token"}
        for method, path in _GUARDED_ENDPOINTS:
            resp = client.request(method, path, headers=headers)
            assert resp.status_code == 401

    def test_valid_admin_token_succeeds(self, client: TestClient, auth_headers: dict) -> None:
        for method, path in _GUARDED_ENDPOINTS:
            resp = client.request(method, path, headers=auth_headers)
            assert resp.status_code == 200, f"{method} {path} rejected valid token"

    def test_valid_viewer_token_succeeds(self, client: TestClient, viewer_headers: dict) -> None:
        for method, path in _GUARDED_ENDPOINTS:
            resp = client.request(method, path, headers=viewer_headers)
            assert resp.status_code == 200
