"""Integration tests for the Prometheus-compatible /metrics endpoint."""
from fastapi.testclient import TestClient

from api.middleware.metrics import reset_metrics

BASE = "/web/api/v2.1"


class TestMetricsEndpoint:
    """Tests for GET /metrics."""

    def test_metrics_returns_200(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]
        assert "version=0.0.4" in resp.headers["content-type"]

    def test_metrics_no_auth_required(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_contains_help_and_type(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        reset_metrics()
        # Generate at least one data point
        client.get(f"{BASE}/system/status")
        resp = client.get("/metrics")
        body = resp.text
        assert "# HELP http_requests_total" in body
        assert "# TYPE http_requests_total counter" in body
        assert "# HELP http_request_duration_seconds" in body
        assert "# TYPE http_request_duration_seconds histogram" in body


class TestMetricsCounters:
    """Tests that requests correctly increment counters."""

    def test_counter_increments(self, client: TestClient) -> None:
        reset_metrics()
        client.get(f"{BASE}/system/status")
        client.get(f"{BASE}/system/status")
        resp = client.get("/metrics")
        body = resp.text
        # Should have at least 2 requests for the status path
        for line in body.splitlines():
            if "http_requests_total" in line and "/system/status" in line:
                count = int(line.split()[-1])
                assert count >= 2
                break
        else:
            raise AssertionError("Expected counter for /system/status not found")

    def test_counter_records_status_code(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        reset_metrics()
        # 200 response
        client.get(f"{BASE}/system/status")
        # 401 response (no auth on protected endpoint)
        client.get(f"{BASE}/system/info")
        resp = client.get("/metrics")
        body = resp.text
        assert 'status="200"' in body
        assert 'status="401"' in body

    def test_counter_records_method(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        reset_metrics()
        client.get(f"{BASE}/system/status")
        resp = client.get("/metrics")
        body = resp.text
        assert 'method="GET"' in body


class TestMetricsHistogram:
    """Tests for duration histogram format and buckets."""

    def test_histogram_has_proper_buckets(self, client: TestClient) -> None:
        reset_metrics()
        client.get(f"{BASE}/system/status")
        resp = client.get("/metrics")
        body = resp.text
        expected_buckets = [
            "0.005", "0.01", "0.025", "0.05", "0.1",
            "0.25", "0.5", "1.0", "2.5", "5.0", "10.0", "+Inf",
        ]
        for bucket in expected_buckets:
            assert f'le="{bucket}"' in body, f"Missing bucket le={bucket}"

    def test_histogram_has_sum_and_count(self, client: TestClient) -> None:
        reset_metrics()
        client.get(f"{BASE}/system/status")
        resp = client.get("/metrics")
        body = resp.text
        assert "http_request_duration_seconds_sum" in body
        assert "http_request_duration_seconds_count" in body

    def test_histogram_buckets_are_cumulative(self, client: TestClient) -> None:
        reset_metrics()
        client.get(f"{BASE}/system/status")
        resp = client.get("/metrics")
        body = resp.text
        # Extract bucket values for system/status only (exclude _sum and _count)
        bucket_values = []
        for line in body.splitlines():
            if (
                "http_request_duration_seconds_bucket" in line
                and "/system/status" in line
            ):
                val = int(line.split()[-1])
                bucket_values.append(val)
        assert len(bucket_values) == 12, f"Expected 12 buckets, got {len(bucket_values)}"
        for i in range(1, len(bucket_values)):
            assert bucket_values[i] >= bucket_values[i - 1], (
                f"Buckets not cumulative: {bucket_values}"
            )


class TestPathNormalization:
    """Tests that UUIDs and numeric IDs in paths are collapsed to {id}."""

    def test_uuid_normalized(self, client: TestClient, auth_headers: dict) -> None:
        reset_metrics()
        client.get(
            f"{BASE}/agents/550e8400-e29b-41d4-a716-446655440000",
            headers=auth_headers,
        )
        resp = client.get("/metrics")
        body = resp.text
        assert "550e8400-e29b-41d4-a716-446655440000" not in body
        assert "/agents/{id}" in body

    def test_numeric_id_normalized(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        reset_metrics()
        client.get(f"{BASE}/groups/123456", headers=auth_headers)
        resp = client.get("/metrics")
        body = resp.text
        assert "123456" not in body
        assert "/groups/{id}" in body


class TestMetricsSkipPaths:
    """Tests that /_dev/ and /metrics paths are excluded from collection."""

    def test_metrics_path_excluded(self, client: TestClient) -> None:
        reset_metrics()
        # Only request /metrics itself
        client.get("/metrics")
        resp = client.get("/metrics")
        body = resp.text
        # The /metrics path itself should not appear in the collected metrics
        assert 'path="/metrics"' not in body

    def test_dev_path_excluded(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        reset_metrics()
        client.get(f"{BASE}/_dev/request-log", headers=auth_headers)
        resp = client.get("/metrics")
        body = resp.text
        assert "/_dev/" not in body
