"""Integration tests for HTTP request audit log endpoints.

GET    /_dev/requests  — list recent request log entries
DELETE /_dev/requests  — clear the request audit log

These tests supplement the basic coverage in test_dev_endpoints.py with
edge-case and behaviour-focused assertions.
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
REQUESTS_URL = f"{BASE}/_dev/requests"


class TestListRequestLog:
    """Tests for GET /_dev/requests."""

    def test_returns_data_list(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(REQUESTS_URL, headers=auth_headers).json()
        assert isinstance(body["data"], list)

    def test_returns_pagination(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(REQUESTS_URL, headers=auth_headers).json()
        assert "pagination" in body
        assert "totalItems" in body["pagination"]

    def test_logs_grow_after_requests(self, client: TestClient, auth_headers: dict) -> None:
        # Clear first to get a clean slate
        client.delete(REQUESTS_URL, headers=auth_headers)
        # Make a few tracked requests
        client.get(f"{BASE}/agents", headers=auth_headers)
        client.get(f"{BASE}/sites", headers=auth_headers)
        body = client.get(REQUESTS_URL, headers=auth_headers).json()
        # At least the two GET requests above should be logged
        assert body["pagination"]["totalItems"] >= 2

    def test_limit_parameter_caps_results(self, client: TestClient, auth_headers: dict) -> None:
        # Generate some traffic
        for _ in range(5):
            client.get(f"{BASE}/agents", headers=auth_headers)
        body = client.get(REQUESTS_URL, headers=auth_headers, params={"limit": 2}).json()
        assert len(body["data"]) <= 2

    def test_log_entry_has_expected_shape(self, client: TestClient, auth_headers: dict) -> None:
        # Ensure there is at least one logged request
        client.get(f"{BASE}/agents", headers=auth_headers)
        body = client.get(REQUESTS_URL, headers=auth_headers).json()
        if body["data"]:
            entry = body["data"][0]
            # Core fields expected on a request log entry
            assert "id" in entry
            assert "method" in entry
            assert "path" in entry

    def test_newest_first_ordering(self, client: TestClient, auth_headers: dict) -> None:
        client.delete(REQUESTS_URL, headers=auth_headers)
        client.get(f"{BASE}/agents", headers=auth_headers)
        client.get(f"{BASE}/sites", headers=auth_headers)
        body = client.get(REQUESTS_URL, headers=auth_headers).json()
        entries = body["data"]
        if len(entries) >= 2 and "timestamp" in entries[0]:
            assert entries[0]["timestamp"] >= entries[1]["timestamp"]


class TestClearRequestLog:
    """Tests for DELETE /_dev/requests."""

    def test_clear_returns_affected_count(self, client: TestClient, auth_headers: dict) -> None:
        # Generate some traffic first
        client.get(f"{BASE}/agents", headers=auth_headers)
        body = client.delete(REQUESTS_URL, headers=auth_headers).json()
        assert "data" in body
        assert "affected" in body["data"]
        assert isinstance(body["data"]["affected"], int)

    def test_clear_empties_the_log(self, client: TestClient, auth_headers: dict) -> None:
        client.get(f"{BASE}/agents", headers=auth_headers)
        client.delete(REQUESTS_URL, headers=auth_headers)
        body = client.get(REQUESTS_URL, headers=auth_headers).json()
        # Only the GET /_dev/requests itself might appear; the log from before is gone
        # totalItems should reflect minimal entries post-clear
        assert body["pagination"]["totalItems"] <= 1

    def test_clear_twice_second_returns_zero_or_minimal(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        client.delete(REQUESTS_URL, headers=auth_headers)
        body = client.delete(REQUESTS_URL, headers=auth_headers).json()
        # Second clear should have very few (or zero) entries to remove
        assert body["data"]["affected"] <= 1

    def test_clear_requires_auth(self, client: TestClient) -> None:
        resp = client.delete(REQUESTS_URL)
        assert resp.status_code == 401

    def test_list_requires_auth(self, client: TestClient) -> None:
        resp = client.get(REQUESTS_URL)
        assert resp.status_code == 401
