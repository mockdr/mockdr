"""Integration tests for Splunk saved search endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestSavedSearches:
    """Tests for /services/saved/searches endpoints."""

    def test_list_saved_searches(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/saved/searches", headers=_auth())
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        assert len(body["entry"]) >= 3  # pre-seeded searches

    def test_get_saved_search(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/saved/searches/SentinelOne Threats - Last 24h",
            headers=_auth(),
        )
        assert resp.status_code == 200
        content = resp.json()["entry"][0]["content"]
        assert "search" in content
        assert "sentinelone" in content["search"]

    def test_create_saved_search(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches",
            json={"name": "Test Search", "search": "search index=main | head 10"},
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_update_saved_search(self, client: TestClient) -> None:
        # Create first
        client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches",
            json={"name": "Update Me", "search": "search index=main"},
            headers=_auth(),
        )
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches/Update Me",
            json={"search": "search index=crowdstrike"},
            headers=_auth(),
        )
        assert resp.status_code == 200
        content = resp.json()["entry"][0]["content"]
        assert "crowdstrike" in content["search"]

    def test_delete_saved_search(self, client: TestClient) -> None:
        client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches",
            json={"name": "Delete Me", "search": "search index=main"},
            headers=_auth(),
        )
        resp = client.delete(
            f"{SPLUNK_PREFIX}/services/saved/searches/Delete Me",
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_dispatch_saved_search(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches/SentinelOne Threats - Last 24h/dispatch",
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert "sid" in resp.json()

    def test_get_dispatch_history(self, client: TestClient) -> None:
        # Dispatch first
        client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches/SentinelOne Threats - Last 24h/dispatch",
            headers=_auth(),
        )
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/saved/searches/SentinelOne Threats - Last 24h/history",
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert len(resp.json()["entry"]) >= 1
