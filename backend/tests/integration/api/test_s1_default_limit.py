"""A SentinelOne list page is ten long unless the client asks otherwise.

``limit`` carries ``default: 10`` on every list route the mock serves (122 GET
operations in ``data/swagger_2_1.json``); the mock defaulted to 25. A client
relying on the default got pages two and a half times the product's size,
so a paging loop exercised here walked a different number of pages in
production.

``/agents/applications`` and ``/agents/processes`` take only ``ids`` in the
swagger and answer without a pagination block, so they answer every row;
the page size the mock gives them is its own and must not cut them short.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


class TestDefaultLimit:
    """No ``limit`` means ten."""

    @pytest.mark.parametrize("path", [
        "/agents", "/threats", "/activities", "/exclusions",
        "/cloud-detection/rules", "/agents/passphrases",
    ])
    def test_a_page_is_ten_long(self, client: TestClient, path: str) -> None:
        body = client.get(f"{BASE}{path}", headers=S1).json()
        assert body["pagination"]["totalItems"] > 10, "needs more than a page of seed"
        assert len(body["data"]) == 10
        assert body["pagination"]["nextCursor"] is not None

    def test_an_explicit_limit_still_wins(self, client: TestClient) -> None:
        body = client.get(f"{BASE}/agents", headers=S1, params={"limit": 25}).json()
        assert len(body["data"]) == 25


class TestUnpaginatedRoutesAnswerEverything:
    """The two per-agent routes the swagger does not paginate are not cut short."""

    def test_applications_are_all_answered(self, client: TestClient) -> None:
        agents = client.get(f"{BASE}/agents", headers=S1, params={"limit": 1000}).json()["data"]
        counts = {
            a["id"]: len(client.get(f"{BASE}/agents/applications", headers=S1,
                                    params={"ids": a["id"], "limit": 1000}).json()["data"])
            for a in agents[:10]
        }
        agent_id = max(counts, key=lambda a: counts[a])
        if counts[agent_id] <= 10:
            pytest.skip("no seeded agent has more than ten applications")
        default = client.get(f"{BASE}/agents/applications", headers=S1,
                             params={"ids": agent_id}).json()["data"]
        assert len(default) == counts[agent_id]
