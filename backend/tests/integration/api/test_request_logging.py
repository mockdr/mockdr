"""Tests for the RequestLoggingMiddleware (request ID + structured logging)."""
from __future__ import annotations

import json
import logging
import uuid

from fastapi.testclient import TestClient

_ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


class TestRequestIdHeader:
    """X-Request-Id should be present on every response."""

    def test_response_contains_request_id(self, client: TestClient) -> None:
        """A fresh UUID should be generated when no incoming header is sent."""
        resp = client.get("/web/api/v2.1/system/status", headers=_ADMIN)
        rid = resp.headers.get("x-request-id")
        assert rid is not None
        # Must be a valid UUID-4.
        uuid.UUID(rid, version=4)

    def test_passthrough_request_id(self, client: TestClient) -> None:
        """An incoming X-Request-Id header should be echoed back verbatim."""
        custom_id = "my-upstream-trace-0001"
        resp = client.get(
            "/web/api/v2.1/system/status",
            headers={**_ADMIN, "X-Request-Id": custom_id},
        )
        assert resp.headers.get("x-request-id") == custom_id

    def test_request_id_on_error_response(self, client: TestClient) -> None:
        """Even a 401 (unauthenticated) response should carry the header."""
        resp = client.get("/web/api/v2.1/agents")
        assert resp.status_code == 401
        assert resp.headers.get("x-request-id") is not None


class TestRequestLogging:
    """Structured log output should include the request_id field."""

    def test_log_contains_request_id(
        self, client: TestClient, caplog: logging.LogCaptureFixture
    ) -> None:
        """The JSON log line emitted by the middleware must include request_id."""
        from utils.logging import JSONFormatter, RequestIdFilter

        custom_id = "log-test-request-id-42"
        formatter = JSONFormatter()
        rid_filter = RequestIdFilter()

        # Attach the filter to caplog's handler so request_id is captured
        # on each record at logging time (while the contextvar is still set).
        caplog.handler.addFilter(rid_filter)
        try:
            with caplog.at_level(logging.INFO, logger="mockdr.request"):
                client.get(
                    "/web/api/v2.1/system/status",
                    headers={**_ADMIN, "X-Request-Id": custom_id},
                )
        finally:
            caplog.handler.removeFilter(rid_filter)

        # Find the log record from our logger and format it with JSONFormatter.
        found = False
        for record in caplog.records:
            if record.name == "mockdr.request":
                line = record.getMessage()
                assert "system/status" in line

                # Use our JSONFormatter to produce the structured output.
                output = formatter.format(record)
                parsed = json.loads(output)
                assert parsed["request_id"] == custom_id
                assert parsed["level"] == "INFO"
                assert "timestamp" in parsed
                assert parsed["logger"] == "mockdr.request"
                found = True
                break
        assert found, "Expected a log record from mockdr.request logger"
