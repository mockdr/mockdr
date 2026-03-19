"""Integration tests for Sentinel watchlist endpoints."""
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={"client_id": "sentinel-mock-client-id",
              "client_secret": "sentinel-mock-client-secret",
              "grant_type": "client_credentials"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestWatchlists:
    """Tests for watchlist CRUD."""

    def test_list_watchlists(self, client: TestClient) -> None:
        resp = client.get(f"{SENTINEL_PREFIX}{_WS}/watchlists", headers=_auth(client))
        assert resp.status_code == 200
        body = resp.json()
        assert "value" in body
        aliases = [w["name"] for w in body["value"]]
        assert "VIP_Users" in aliases
        assert "HighValueAssets" in aliases

    def test_get_watchlist(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/VIP_Users",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert resp.json()["properties"]["displayName"] == "VIP Users"

    def test_create_watchlist(self, client: TestClient) -> None:
        headers = _auth(client)
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/TestWatchlist",
            json={"properties": {
                "displayName": "Test Watchlist",
                "description": "Created by test",
                "itemsSearchKey": "Name",
            }},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_delete_watchlist(self, client: TestClient) -> None:
        headers = _auth(client)
        client.put(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/ToDelete",
            json={"properties": {"displayName": "Delete Me"}},
            headers=headers,
        )
        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/ToDelete",
            headers=headers,
        )
        assert resp.status_code == 200


class TestWatchlistItems:
    """Tests for watchlist item CRUD."""

    def test_list_items(self, client: TestClient) -> None:
        resp = client.get(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/VIP_Users/watchlistItems",
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert len(resp.json()["value"]) >= 5

    def test_create_item(self, client: TestClient) -> None:
        headers = _auth(client)
        resp = client.put(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/VIP_Users/watchlistItems/new-item-001",
            json={"properties": {"itemsKeyValue": {"UserPrincipalName": "test@test.com"}}},
            headers=headers,
        )
        assert resp.status_code == 200

    def test_delete_item(self, client: TestClient) -> None:
        headers = _auth(client)
        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/VIP_Users/watchlistItems/vip-1",
            headers=headers,
        )
        assert resp.status_code == 200
