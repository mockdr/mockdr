"""``countOnly=true`` answers the total without the objects.

The 2.1 swagger documents ``countOnly`` on 120 list operations — every list
route the mock serves — as "If true, only total number of items will be
returned, without any of the actual objects." No route read it: a client
asking how many threats match was sent the first page of them as well, and
one asking with ``limit=1000`` to learn the count fetched a thousand records
it threw away.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


class TestCountOnly:
    """The total is kept; the objects and the cursor are not."""

    @pytest.mark.parametrize("path", [
        "/agents", "/threats", "/activities", "/groups", "/users", "/exclusions",
        "/cloud-detection/alerts", "/cloud-detection/rules", "/agents/tags",
        "/threat-intelligence/iocs",
    ])
    def test_only_the_total(self, client: TestClient, path: str) -> None:
        whole = client.get(f"{BASE}{path}", headers=S1, params={"limit": 1000}).json()
        counted = client.get(f"{BASE}{path}", headers=S1,
                             params={"countOnly": "true", "limit": 1000}).json()
        assert counted["data"] == []
        assert counted["pagination"]["totalItems"] == whole["pagination"]["totalItems"]
        assert counted["pagination"]["nextCursor"] is None

    def test_the_count_follows_the_filter(self, client: TestClient) -> None:
        filtered = client.get(f"{BASE}/agents", headers=S1,
                              params={"osTypes": "windows", "limit": 1000}).json()
        counted = client.get(f"{BASE}/agents", headers=S1,
                             params={"osTypes": "windows", "countOnly": "true"}).json()
        assert counted["pagination"]["totalItems"] == len(filtered["data"]) > 0

    def test_sites_keep_their_summary(self, client: TestClient) -> None:
        counted = client.get(f"{BASE}/sites", headers=S1, params={"countOnly": "true"}).json()
        assert counted["data"]["sites"] == []
        assert "allSites" in counted["data"]
        assert counted["pagination"]["totalItems"] >= 1

    def test_false_lists_as_usual(self, client: TestClient) -> None:
        body = client.get(f"{BASE}/threats", headers=S1,
                          params={"countOnly": "false", "limit": 2}).json()
        assert len(body["data"]) == 2
