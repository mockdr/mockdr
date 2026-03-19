"""Integration tests for the HTTP request audit log endpoints.

GET    /_dev/requests  — list recent audit log entries
DELETE /_dev/requests  — clear the audit log
"""
from fastapi.testclient import TestClient


class TestAuditLog:
    """Tests for GET /_dev/requests and DELETE /_dev/requests."""

    def test_get_requests_returns_200_with_data_list(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get("/web/api/v2.1/_dev/requests", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)
        assert "pagination" in body

    def test_after_api_call_request_appears_in_log(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        # Make a real API call
        client.get("/web/api/v2.1/agents", headers=auth_headers)
        # Now check the audit log
        resp = client.get("/web/api/v2.1/_dev/requests", headers=auth_headers)
        assert resp.status_code == 200
        logs = resp.json()["data"]
        paths = [entry["path"] for entry in logs]
        assert "/web/api/v2.1/agents" in paths

    def test_delete_requests_clears_log(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        # Make some calls to populate the log
        client.get("/web/api/v2.1/agents", headers=auth_headers)
        client.get("/web/api/v2.1/threats", headers=auth_headers)

        # Clear the log
        del_resp = client.delete("/web/api/v2.1/_dev/requests", headers=auth_headers)
        assert del_resp.status_code == 200
        assert "affected" in del_resp.json()["data"]

        # Log should now be empty (only the DELETE itself might be there, but
        # /_dev/requests paths are excluded from logging entirely)
        resp = client.get("/web/api/v2.1/_dev/requests", headers=auth_headers)
        # The DELETE /_dev/requests path is excluded from logging, so log is empty
        non_dev_entries = [
            e for e in resp.json()["data"]
            if "/_dev/requests" not in e["path"]
        ]
        assert non_dev_entries == []

    def test_dev_requests_path_not_in_log(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        # The /_dev/requests endpoint itself must not appear in the log
        client.get("/web/api/v2.1/_dev/requests", headers=auth_headers)
        resp = client.get("/web/api/v2.1/_dev/requests", headers=auth_headers)
        logs = resp.json()["data"]
        paths = [entry["path"] for entry in logs]
        assert "/_dev/requests" not in paths

    def test_log_entries_have_required_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        client.get("/web/api/v2.1/agents", headers=auth_headers)
        resp = client.get("/web/api/v2.1/_dev/requests", headers=auth_headers)
        logs = resp.json()["data"]
        assert len(logs) >= 1
        entry = next(e for e in logs if e["path"] == "/web/api/v2.1/agents")
        for field in ("id", "timestamp", "method", "path", "query_string",
                      "status_code", "duration_ms", "token_hint"):
            assert field in entry, f"Required field '{field}' missing from log entry"
        assert entry["method"] == "GET"
        assert entry["status_code"] == 200
