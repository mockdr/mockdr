"""Integration tests for GET /agents endpoints.

Verifies response shape matches real SentinelOne API contract and that
internal fields are never exposed.
"""
from fastapi.testclient import TestClient

from utils.internal_fields import AGENT_INTERNAL_FIELDS

_INTERNAL = AGENT_INTERNAL_FIELDS


class TestListAgents:
    def test_requires_auth(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/agents")
        assert resp.status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_no_internal_fields_exposed(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers)
        for agent in resp.json()["data"]:
            for field in _INTERNAL:
                assert field not in agent, f"Internal field '{field}' leaked in agent response"

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers)
        agent = resp.json()["data"][0]
        for field in ("id", "uuid", "computerName", "osType", "agentVersion",
                      "networkStatus", "isActive", "siteId", "groupId"):
            assert field in agent, f"Required field '{field}' missing from agent"

    def test_filter_by_os_type(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers, params={"osTypes": "windows"})
        assert resp.status_code == 200
        for agent in resp.json()["data"]:
            assert agent["osType"] == "windows"

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers, params={"limit": 3})
        assert len(resp.json()["data"]) <= 3

    def test_pagination_cursor(self, client: TestClient, auth_headers: dict) -> None:
        r1 = client.get("/web/api/v2.1/agents", headers=auth_headers, params={"limit": 5})
        cursor = r1.json()["pagination"]["nextCursor"]
        if cursor:
            r2 = client.get("/web/api/v2.1/agents", headers=auth_headers,
                            params={"limit": 5, "cursor": cursor})
            assert r2.status_code == 200
            ids1 = {a["id"] for a in r1.json()["data"]}
            ids2 = {a["id"] for a in r2.json()["data"]}
            assert ids1.isdisjoint(ids2), "Cursor pagination returned overlapping results"


class TestGetAgent:
    def test_returns_single_agent(self, client: TestClient, auth_headers: dict) -> None:
        agents = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"]
        agent_id = agents[0]["id"]
        resp = client.get(f"/web/api/v2.1/agents/{agent_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == agent_id

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404

    def test_no_internal_fields_in_single(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]["id"]
        agent = client.get(f"/web/api/v2.1/agents/{agent_id}", headers=auth_headers).json()["data"]
        for field in _INTERNAL:
            assert field not in agent


class TestAgentCount:
    def test_returns_count_dict(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents/count", headers=auth_headers)
        assert resp.status_code == 200
        assert "count" in resp.json()["data"]
        assert isinstance(resp.json()["data"]["count"], int)

    def test_count_matches_list_total(self, client: TestClient, auth_headers: dict) -> None:
        total = client.get("/web/api/v2.1/agents", headers=auth_headers,
                           params={"limit": 1}).json()["pagination"]["totalItems"]
        count = client.get("/web/api/v2.1/agents/count", headers=auth_headers).json()["data"]["count"]
        assert count == total
