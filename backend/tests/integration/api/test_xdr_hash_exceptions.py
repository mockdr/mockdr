"""Integration tests for Cortex XDR Hash Exceptions endpoints.

Covers seeded data retrieval, blocklist/allowlist CRUD operations,
RBAC enforcement, and XDR reply envelope invariants.
"""
import hashlib
import secrets
import time

from fastapi.testclient import TestClient

XDR_PREFIX = "/xdr/public_api/v1"


def _xdr_headers(
    key_id: str = "1",
    key_secret: str = "xdr-admin-secret",
) -> dict[str, str]:
    """Build valid XDR advanced-auth headers."""
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    auth_hash = hashlib.sha256((key_secret + nonce + timestamp).encode()).hexdigest()
    return {
        "x-xdr-auth-id": key_id,
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": auth_hash,
    }




class TestAddToBlocklist:
    """Tests for POST /hash_exceptions/blocklist/."""

    def test_add_hash_to_blocklist(self, client: TestClient) -> None:
        """Adding a hash to blocklist returns success.

        ``hash_list`` is a flat list of SHA256 strings and ``comment`` its
        sibling — the shape Cortex's own client builds.
        """
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/blocklist/",
            json={"request_data": {
                "hash_list": [
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b851",
                ],
                "comment": "Test blocklist entry",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True


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



class TestAddToAllowlist:
    """Tests for POST /hash_exceptions/allowlist/."""

    def test_add_hash_to_allowlist(self, client: TestClient) -> None:
        """Adding a hash to allowlist returns success.

        ``hash_list`` is a flat list of SHA256 strings and ``comment`` its
        sibling — the shape Cortex's own client builds.
        """
        resp = client.post(
            f"{XDR_PREFIX}/hash_exceptions/allowlist/",
            json={"request_data": {
                "hash_list": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8552"],
                "comment": "Safe application",
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True



class TestRemoveFromAllowlist:
    """Tests for POST /hash_exceptions/allowlist/remove/."""



class TestAuthEnforcement:
    """Tests for HMAC auth enforcement on hash exception endpoints."""


