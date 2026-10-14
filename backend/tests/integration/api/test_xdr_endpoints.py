"""Integration tests for Cortex XDR Endpoints API.

Verifies endpoint listing, filtering, isolation, scanning, deletion,
policy retrieval, agent name updates, and file operations.
"""
import hashlib
import secrets
import time

import pytest
from fastapi.testclient import TestClient

XDR_PREFIX = "/xdr/public_api/v1"


def _xdr_headers(
    key_id: str = "1",
    key_secret: str = "xdr-admin-secret",
) -> dict[str, str]:
    """Build valid XDR HMAC auth headers."""
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    # Advanced auth: SHA-256 over key + nonce + timestamp, plainly concatenated
    auth_hash = hashlib.sha256((key_secret + nonce + timestamp).encode()).hexdigest()
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
        # Pending until the agent acknowledges (see TestIsolationSettles).
        assert ep["is_isolated"] == "AGENT_PENDING_ISOLATION"

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
        assert ep["is_isolated"] == "AGENT_PENDING_ISOLATION_CANCELLATION"

    def test_isolate_nonexistent_returns_500(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": "nonexistent-endpoint"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 500


def _endpoint(client: TestClient, endpoint_id: str) -> dict:
    resp = client.post(
        f"{XDR_PREFIX}/endpoints/get_endpoint/",
        json={"request_data": {"endpoint_id_list": [endpoint_id]}},
        headers=_xdr_headers(),
    )
    return resp.json()["reply"]["endpoints"][0]


class TestIsolationSettles:
    """`is_isolated` speaks Cortex's `AGENT_*` words, and isolation is asynchronous.

    The mock stored `isolated`/`unisolated` and flipped at once. Cortex serves
    `AGENT_ISOLATED`, `AGENT_UNISOLATED`, `AGENT_PENDING_ISOLATION` and
    `AGENT_PENDING_ISOLATION_CANCELLATION` (XSOAR CortexXDR test_data
    get_endpoints.json; CoreIRApiModule `isolate_endpoint_command` and
    `unisolate_endpoint_command` branch on all four), and the XSOAR
    `xdr-endpoint-isolate` command polls `is_isolated` until it reads
    `AGENT_ISOLATED` — which against the mock it never did.
    """

    def _unisolated_id(self, client: TestClient) -> str:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"filters": [
                {"field": "isolate", "operator": "in", "value": ["unisolated"]},
            ]}},
            headers=_xdr_headers(),
        )
        endpoints = resp.json()["reply"]["endpoints"]
        assert endpoints and all(e["is_isolated"] == "AGENT_UNISOLATED" for e in endpoints)
        return endpoints[0]["endpoint_id"]

    def test_the_seeded_fleet_uses_the_wire_words(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {}}, headers=_xdr_headers(),
        )
        states = {e["is_isolated"] for e in resp.json()["reply"]["endpoints"]}
        assert states == {"AGENT_ISOLATED", "AGENT_UNISOLATED"}

    def test_isolate_is_pending_then_isolated(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        settle = "application.settling.SETTLE_SECONDS"
        endpoint_id = self._unisolated_id(client)
        client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": endpoint_id}}, headers=_xdr_headers(),
        )
        assert _endpoint(client, endpoint_id)["is_isolated"] == "AGENT_PENDING_ISOLATION"

        monkeypatch.setattr(settle, -1.0)
        assert _endpoint(client, endpoint_id)["is_isolated"] == "AGENT_ISOLATED"

        client.post(
            f"{XDR_PREFIX}/endpoints/unisolate",
            json={"request_data": {"endpoint_id": endpoint_id}}, headers=_xdr_headers(),
        )
        monkeypatch.setattr(settle, 60.0)
        ep = _endpoint(client, endpoint_id)
        assert ep["is_isolated"] == "AGENT_PENDING_ISOLATION_CANCELLATION"
        assert "isolation_requested_at" not in ep, "mockdr's bookkeeping leaked"
        monkeypatch.setattr(settle, -1.0)
        assert _endpoint(client, endpoint_id)["is_isolated"] == "AGENT_UNISOLATED"

    def test_a_completed_action_means_the_endpoint_is_isolated(
        self, client: TestClient,
    ) -> None:
        endpoint_id = self._unisolated_id(client)
        action_id = client.post(
            f"{XDR_PREFIX}/endpoints/isolate",
            json={"request_data": {"endpoint_id": endpoint_id}}, headers=_xdr_headers(),
        ).json()["reply"]["action_id"]
        status = client.post(
            f"{XDR_PREFIX}/actions/get_action_status/",
            json={"request_data": {"group_action_id": action_id}}, headers=_xdr_headers(),
        ).json()["reply"]["data"]
        assert status[endpoint_id] == "COMPLETED_SUCCESSFULLY"
        assert _endpoint(client, endpoint_id)["is_isolated"] == "AGENT_ISOLATED"

    def test_the_isolate_filter_still_takes_the_lower_case_words(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/get_endpoint/",
            json={"request_data": {"filters": [
                {"field": "isolate", "operator": "in", "value": ["isolated"]},
            ]}},
            headers=_xdr_headers(),
        )
        endpoints = resp.json()["reply"]["endpoints"]
        assert endpoints and {e["is_isolated"] for e in endpoints} == {"AGENT_ISOLATED"}


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
        """The target is named by a ``filters`` block, as Cortex documents."""
        endpoint_id = _get_first_endpoint_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/endpoints/update_agent_name/",
            json={"request_data": {
                "filters": [{"field": "endpoint_id_list", "operator": "in",
                             "value": [endpoint_id]}],
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
