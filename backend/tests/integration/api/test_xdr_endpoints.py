"""Integration tests for Cortex XDR Endpoints API.

Verifies endpoint listing, filtering, isolation, scanning, deletion,
policy retrieval, agent name updates, and file operations.
"""
import hashlib
import hmac
import secrets
import time

from fastapi.testclient import TestClient

XDR_PREFIX = "/xdr/public_api/v1"


def _xdr_headers(
    key_id: str = "1",
    key_secret: str = "xdr-admin-secret",
) -> dict[str, str]:
    """Build valid XDR HMAC auth headers."""
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    # HMAC-SHA256: key_secret as HMAC key, nonce:timestamp as message
    auth_hash = hmac.new(key_secret.encode(), (nonce + ":" + timestamp).encode(), hashlib.sha256).hexdigest()
    return {
        "x-xdr-auth-id": key_id,
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": auth_hash,
    }


def _get_first_endpoint_id(client: TestClient) -> str:
    """Return the first endpoint ID from the listing."""
    resp = client.post(
        f"{XDR_PREFIX}/endpoints/get_endpoint/",
        json={"request_data": {}},
        headers=_xdr_headers(),
    )
    return resp.json()["reply"]["endpoints"][0]["endpoint_id"]


class TestGetEndpoints:
    """Tests for POST /endpoints/get_endpoint/."""

    def test_get_endpoints_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_response_has_reply_envelope(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        body = resp.json()
        assert "reply" in body
        reply = body["reply"]
        assert "total_count" in reply
        assert "result_count" in reply
        assert "endpoints" in reply

    def test_endpoints_have_expected_fields(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        endpoints = resp.json()["reply"]["endpoints"]
        assert len(endpoints) > 0
        ep = endpoints[0]
        required_fields = [
            "endpoint_id", "endpoint_name", "endpoint_type",
            "endpoint_status", "os_type", "ip", "domain",
            "first_seen", "last_seen", "is_isolated",
            "operational_status", "scan_status",
        ]
        for field in required_fields:
            assert field in ep, f"Required field '{field}' missing from endpoint"

    def test_filter_by_endpoint_status(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {
                "filters": [{"field": "endpoint_status", "value": ["connected"]}],
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        for ep in resp.json()["reply"]["endpoints"]:
            assert ep["endpoint_status"] == "connected"

    def test_filter_by_endpoint_id_list(self, client: TestClient) -> None:
        """Top-level endpoint_id_list filter returns specific endpoints."""
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        endpoints = resp.json()["reply"]["endpoints"]
        assert len(endpoints) == 1
        assert endpoints[0]["endpoint_id"] == endpoint_id

    def test_pagination(self, client: TestClient) -> None:
        headers = _xdr_headers()
        r1 = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"search_from": 0, "search_to": 2}},
            headers=headers,
        )
        r2 = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"search_from": 2, "search_to": 4}},
            headers=headers,
        )
        ids1 = {e["endpoint_id"] for e in r1.json()["reply"]["endpoints"]}
        ids2 = {e["endpoint_id"] for e in r2.json()["reply"]["endpoints"]}
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"


class TestIsolateEndpoint:
    """Tests for POST /endpoints/isolate and /endpoints/unisolate."""

    def test_isolate_endpoint(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": endpoint_id}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "action_id" in resp.json()["reply"]

        # Verify isolation status
        get_resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        ep = get_resp.json()["reply"]["endpoints"][0]
        assert ep["is_isolated"] == "isolated"

    def test_unisolate_endpoint(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)

        # Isolate first
        client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": endpoint_id}},
            headers=_xdr_headers(),
        )

        # Then unisolate
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/unisolate",
            json={"request_data": {"endpoint_id": endpoint_id}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "action_id" in resp.json()["reply"]

        # Verify
        get_resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        ep = get_resp.json()["reply"]["endpoints"][0]
        assert ep["is_isolated"] == "unisolated"

    def test_isolate_nonexistent_returns_500(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": "nonexistent-endpoint"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 500


class TestScanEndpoint:
    """Tests for POST /endpoints/scan/."""

    def test_scan_endpoint(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/scan/",
            json={"request_data": {"endpoint_id": endpoint_id}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "action_id" in resp.json()["reply"]

        # Verify scan_status changed
        get_resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        ep = get_resp.json()["reply"]["endpoints"][0]
        assert ep["scan_status"] == "in_progress"


class TestDeleteEndpoints:
    """Tests for POST /endpoints/delete/."""

    def test_delete_endpoint(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/delete/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

        # Verify deleted
        get_resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        assert get_resp.json()["reply"]["endpoints"] == []


class TestGetPolicy:
    """Tests for POST /endpoints/get_policy/."""

    def test_get_policy(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_policy/",
            json={"request_data": {"endpoint_id": endpoint_id}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        policy = resp.json()["reply"]
        assert policy["endpoint_id"] == endpoint_id
        assert "policy_name" in policy
        assert "rules" in policy

    def test_get_policy_nonexistent_returns_500(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_policy/",
            json={"request_data": {"endpoint_id": "nonexistent"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 500


class TestUpdateAgentName:
    """Tests for POST /endpoints/update_agent_name/."""

    def test_update_agent_name(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/update_agent_name/",
            json={"request_data": {
                "endpoint_id": endpoint_id,
                "alias": "My Custom Name",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

        # Verify alias persisted
        get_resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"endpoint_id_list": [endpoint_id]}},
            headers=_xdr_headers(),
        )
        ep = get_resp.json()["reply"]["endpoints"][0]
        assert ep["alias"] == "My Custom Name"


class TestFileOperations:
    """Tests for quarantine, restore, and file_retrieval endpoints."""

    def test_quarantine_file(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/quarantine/",
            json={"request_data": {
                "endpoint_id": endpoint_id,
                "file_path": "C:\\malware.exe",
                "file_hash": "a" * 64,
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "action_id" in resp.json()["reply"]

    def test_restore_file(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/restore/",
            json={"request_data": {
                "endpoint_id": endpoint_id,
                "file_hash": "a" * 64,
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "action_id" in resp.json()["reply"]

    def test_file_retrieval(self, client: TestClient) -> None:
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/file_retrieval/",
            json={"request_data": {
                "endpoint_id": endpoint_id,
                "file_path": "C:\\evidence\\sample.exe",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert "action_id" in resp.json()["reply"]

    def test_quarantine_nonexistent_endpoint_returns_500(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/quarantine/",
            json={"request_data": {
                "endpoint_id": "nonexistent",
                "file_path": "C:\\malware.exe",
                "file_hash": "a" * 64,
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 500
