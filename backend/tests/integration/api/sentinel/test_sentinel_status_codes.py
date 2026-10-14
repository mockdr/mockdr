"""Create Or Update answers 201 or 200; Delete answers 200 or 204.

Every PUT and DELETE in the Sentinel 2024-03-01 specification
(`data/vendor-specs/sentinel_2024-03-01_*.json`; the Incidents - Create Or
Update and Incidents - Delete pages on learn.microsoft.com list the same)
declares exactly two success codes: `200 OK` / `201 Created` for a PUT that
replaced / created, and `200 OK` / `204 No Content` for a DELETE that removed
something / found nothing to remove — ARM's convention, also written into the
Azure REST API guidelines: "return a 204-No Content … even if the URL
identifies a resource that does not exist; do not return 404-Not Found".

The mock answered every PUT 200, so a client could not tell it had created
a resource rather than overwritten one, and every DELETE of a missing
resource 404, which an idempotent delete — or a retry whose first answer was
lost — reads as a failure.
"""
from __future__ import annotations

import pytest
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
              "grant_type": "client_credentials",
              "scope": "https://management.azure.com/.default"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _an_incident(client: TestClient, headers: dict) -> str:
    listing = client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=headers).json()
    return str(listing["value"][0]["name"])


#: (path below the workspace, a valid PUT body). `{incident}` is filled in.
RESOURCES = [
    ("/incidents/status-codes-inc",
     {"properties": {"title": "t", "severity": "Low", "status": "New"}}),
    ("/incidents/{incident}/comments/status-codes-cmt",
     {"properties": {"message": "m"}}),
    ("/alertRules/status-codes-rule",
     {"kind": "Scheduled", "properties": {
         "displayName": "r", "severity": "Low", "query": "SecurityAlert", "enabled": True}}),
    ("/watchlists/StatusCodes",
     {"properties": {"displayName": "w", "itemsSearchKey": "Name", "provider": "p",
                     "source": "s.csv"}}),
    ("/watchlists/VIP_Users/watchlistItems/status-codes-item",
     {"properties": {"itemsKeyValue": {"UserPrincipalName": "a@b.c"}}}),
    ("/bookmarks/status-codes-bm",
     {"properties": {"displayName": "b", "query": "SecurityAlert"}}),
    ("/threatIntelligence/main/indicators/status-codes-ti",
     {"kind": "indicator", "properties": {"displayName": "i", "pattern": "[ipv4-addr:value = '1.2.3.4']",
                                          "source": "mockdr"}}),
]


@pytest.mark.parametrize(("path", "body"), RESOURCES, ids=[p for p, _ in RESOURCES])
class TestEveryResource:
    def test_create_is_201_and_replace_is_200(
        self, client: TestClient, path: str, body: dict,
    ) -> None:
        headers = _auth(client)
        url = f"{SENTINEL_PREFIX}{_WS}{path.format(incident=_an_incident(client, headers))}"
        created = client.put(url, json=body, headers=headers)
        assert created.status_code == 201, created.text
        replaced = client.put(url, json=body, headers=headers)
        assert replaced.status_code == 200, replaced.text

    def test_delete_is_200_then_204(
        self, client: TestClient, path: str, body: dict,
    ) -> None:
        headers = _auth(client)
        url = f"{SENTINEL_PREFIX}{_WS}{path.format(incident=_an_incident(client, headers))}"
        client.put(url, json=body, headers=headers)
        first = client.delete(url, headers=headers)
        assert first.status_code == 200, first.text
        again = client.delete(url, headers=headers)
        assert again.status_code == 204, again.text
        assert again.content == b""


class TestAMissingParentIsStillA404:
    """204 is for a resource that is not there, not for a parent that is not."""

    def test_an_item_of_a_missing_watchlist(self, client: TestClient) -> None:
        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/watchlists/NoSuchList/watchlistItems/x",
            headers=_auth(client),
        )
        assert resp.status_code == 404

    def test_a_comment_of_a_missing_incident(self, client: TestClient) -> None:
        resp = client.delete(
            f"{SENTINEL_PREFIX}{_WS}/incidents/no-such-incident/comments/x",
            headers=_auth(client),
        )
        assert resp.status_code == 404
