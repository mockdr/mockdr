"""Integration tests for Cortex XDR Hash Exceptions endpoints.

Covers seeded data retrieval, blocklist/allowlist CRUD operations,
RBAC enforcement, and XDR reply envelope invariants.
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
    auth_hash = hmac.new(
        key_secret.encode(), (nonce + ":" + timestamp).encode(), hashlib.sha256,
    ).hexdigest()
    return {
        "x-xdr-auth-id": key_id,
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": auth_hash,
    }


class TestGetBlocklist:
    """Tests for POST /hash_exceptions/blocklist/get/."""

    def test_returns_200(self, client: TestClient) -> None:
        """Blocklist get endpoint returns 200 with seeded data."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_has_reply_envelope(self, client: TestClient) -> None:
        """Response uses XDR reply envelope."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        body = resp.json()
        assert "reply" in body
        reply = body["reply"]
        assert "total_count" in reply
        assert "data" in reply

    def test_seeded_blocklist_has_entries(self, client: TestClient) -> None:
        """Seeder creates 6 blocklist entries."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        assert reply["total_count"] == 6
        assert reply["result_count"] == 6
        for entry in reply["data"]:
            assert entry["list_type"] == "blocklist"
            assert entry["hash"] != ""

    def test_blocklist_entries_have_required_fields(self, client: TestClient) -> None:
        """Each entry has exception_id, hash, list_type, comment, created_at."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        for entry in resp.json()["reply"]["data"]:
            assert "exception_id" in entry
            assert "hash" in entry
            assert "list_type" in entry
            assert "comment" in entry
            assert "created_at" in entry


class TestGetAllowlist:
    """Tests for POST /hash_exceptions/allowlist/get/."""

    def test_returns_200(self, client: TestClient) -> None:
        """Allowlist get endpoint returns 200 with seeded data."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/get/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_seeded_allowlist_has_entries(self, client: TestClient) -> None:
        """Seeder creates 4 allowlist entries."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/get/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        assert reply["total_count"] == 4
        for entry in reply["data"]:
            assert entry["list_type"] == "allowlist"


class TestAddToBlocklist:
    """Tests for POST /hash_exceptions/blocklist/."""

    def test_add_hash_to_blocklist(self, client: TestClient) -> None:
        """Adding a hash to blocklist returns success."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/",
            json={"request_data": {"hash_list": [
                {"hash": "abc123def456", "comment": "Test blocklist entry"},
            ]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

    def test_added_hash_appears_in_blocklist(self, client: TestClient) -> None:
        """After adding, the hash is visible in blocklist get."""
        headers = _xdr_headers()
        test_hash = "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678"

        client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/",
            json={"request_data": {"hash_list": [
                {"hash": test_hash, "comment": "Integration test"},
            ]}},
            headers=headers,
        )

        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=headers,
        )
        hashes = [e["hash"] for e in resp.json()["reply"]["data"]]
        assert test_hash in hashes

    def test_viewer_cannot_add_to_blocklist(self, client: TestClient) -> None:
        """Viewer role (key_id=3) is denied write access."""
        headers = _xdr_headers("3", "xdr-viewer-secret")
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/",
            json={"request_data": {"hash_list": [
                {"hash": "test", "comment": "Should fail"},
            ]}},
            headers=headers,
        )
        assert resp.status_code == 403


class TestRemoveFromBlocklist:
    """Tests for POST /hash_exceptions/blocklist/remove/."""

    def test_remove_hash_from_blocklist(self, client: TestClient) -> None:
        """Removing a hash returns success."""
        headers = _xdr_headers()
        test_hash = "removeme1234567890abcdef1234567890abcdef1234567890abcdef12345678"

        # Add first
        client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/",
            json={"request_data": {"hash_list": [
                {"hash": test_hash, "comment": "Will be removed"},
            ]}},
            headers=headers,
        )

        # Remove
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/remove/",
            json={"request_data": {"hash_list": [test_hash]}},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

        # Verify removed
        get_resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=headers,
        )
        hashes = [e["hash"] for e in get_resp.json()["reply"]["data"]]
        assert test_hash not in hashes


class TestAddToAllowlist:
    """Tests for POST /hash_exceptions/allowlist/."""

    def test_add_hash_to_allowlist(self, client: TestClient) -> None:
        """Adding a hash to allowlist returns success."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/",
            json={"request_data": {"hash_list": [
                {"hash": "allowme123", "comment": "Safe application"},
            ]}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

    def test_added_hash_appears_in_allowlist(self, client: TestClient) -> None:
        """After adding, the hash is visible in allowlist get."""
        headers = _xdr_headers()
        test_hash = "safeapp1234567890abcdef1234567890abcdef1234567890abcdef12345678"

        client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/",
            json={"request_data": {"hash_list": [
                {"hash": test_hash, "comment": "Safe"},
            ]}},
            headers=headers,
        )

        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/get/",
            json={"request_data": {}},
            headers=headers,
        )
        hashes = [e["hash"] for e in resp.json()["reply"]["data"]]
        assert test_hash in hashes


class TestRemoveFromAllowlist:
    """Tests for POST /hash_exceptions/allowlist/remove/."""

    def test_remove_hash_from_allowlist(self, client: TestClient) -> None:
        """Full add-then-remove lifecycle for allowlist."""
        headers = _xdr_headers()
        test_hash = "removeallow1234567890abcdef1234567890abcdef1234567890abcdef1234"

        client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/",
            json={"request_data": {"hash_list": [
                {"hash": test_hash, "comment": "Will remove"},
            ]}},
            headers=headers,
        )

        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/remove/",
            json={"request_data": {"hash_list": [test_hash]}},
            headers=headers,
        )
        assert resp.status_code == 200

        get_resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/get/",
            json={"request_data": {}},
            headers=headers,
        )
        hashes = [e["hash"] for e in get_resp.json()["reply"]["data"]]
        assert test_hash not in hashes


class TestAuthEnforcement:
    """Tests for HMAC auth enforcement on hash exception endpoints."""

    def test_missing_auth_returns_401(self, client: TestClient) -> None:
        """Requests without auth headers are rejected."""
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
        )
        assert resp.status_code in (401, 403)

    def test_invalid_auth_returns_401(self, client: TestClient) -> None:
        """Requests with invalid HMAC are rejected."""
        headers = {
            "x-xdr-auth-id": "1",
            "x-xdr-nonce": "fake",
            "x-xdr-timestamp": "0",
            "Authorization": "invalid",
        }
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/get/",
            json={"request_data": {}},
            headers=headers,
        )
        assert resp.status_code in (401, 403)
