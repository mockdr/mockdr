"""Integration tests for Splunk server info endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestServerInfo:
    """Tests for /services/server/* endpoints."""

    def test_server_info_no_auth(self, client: TestClient) -> None:
        """Server info should be accessible without auth (health check)."""
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/info")
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        content = body["entry"][0]["content"]
        assert content["version"] == "9.4.0"
        assert content["product_type"] == "enterprise"

    def test_server_status(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/status", headers=_auth())
        assert resp.status_code == 200
        content = resp.json()["entry"][0]["content"]
        assert content["health"] == "green"

    def test_server_settings(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/settings", headers=_auth())
        assert resp.status_code == 200

    def test_response_envelope_format(self, client: TestClient) -> None:
        """Verify Splunk JSON envelope structure."""
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/info")
        body = resp.json()
        assert "links" in body
        assert "origin" in body
        assert "updated" in body
        assert "generator" in body
        assert "entry" in body
        assert "paging" in body
        assert "version" in body["generator"]
        assert "build" in body["generator"]
        assert "total" in body["paging"]
        assert "perPage" in body["paging"]
        assert "offset" in body["paging"]
