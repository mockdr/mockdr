"""Integration tests for GET /activities endpoints.

Verifies response shape, required fields, and filter behaviour.
Activities have no internal fields — all fields are public per the S1 contract.
"""
from fastapi.testclient import TestClient

_REQUIRED = {"id", "activityType", "primaryDescription", "createdAt", "updatedAt"}


class TestListActivities:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/activities").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/activities", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        act = client.get("/web/api/v2.1/activities", headers=auth_headers).json()["data"][0]
        for field in _REQUIRED:
            assert field in act, f"Required field '{field}' missing from activity"

    def test_activity_type_is_int(self, client: TestClient, auth_headers: dict) -> None:
        act = client.get("/web/api/v2.1/activities", headers=auth_headers).json()["data"][0]
        assert isinstance(act["activityType"], int)

    def test_primary_description_is_string(self, client: TestClient, auth_headers: dict) -> None:
        act = client.get("/web/api/v2.1/activities", headers=auth_headers).json()["data"][0]
        assert isinstance(act["primaryDescription"], str)
        assert len(act["primaryDescription"]) > 0

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/activities", headers=auth_headers, params={"limit": 5})
        assert len(resp.json()["data"]) <= 5

    def test_pagination_cursor(self, client: TestClient, auth_headers: dict) -> None:
        r1 = client.get("/web/api/v2.1/activities", headers=auth_headers, params={"limit": 5})
        cursor = r1.json()["pagination"]["nextCursor"]
        if cursor:
            r2 = client.get("/web/api/v2.1/activities", headers=auth_headers,
                            params={"limit": 5, "cursor": cursor})
            assert r2.status_code == 200
            ids1 = {a["id"] for a in r1.json()["data"]}
            ids2 = {a["id"] for a in r2.json()["data"]}
            assert ids1.isdisjoint(ids2), "Cursor pagination returned overlapping results"

    def test_total_items_positive(self, client: TestClient, auth_headers: dict) -> None:
        total = client.get("/web/api/v2.1/activities", headers=auth_headers).json()["pagination"]["totalItems"]
        assert total > 0

    def test_filter_by_agent_id(self, client: TestClient, auth_headers: dict) -> None:
        """Filter by agentId should only return activities linked to that agent (when present)."""
        activities = client.get("/web/api/v2.1/activities", headers=auth_headers).json()["data"]
        agent_id = next((a["agentId"] for a in activities if a.get("agentId")), None)
        if agent_id:
            resp = client.get("/web/api/v2.1/activities", headers=auth_headers,
                              params={"agentIds": agent_id})
            assert resp.status_code == 200
            for act in resp.json()["data"]:
                assert act["agentId"] == agent_id
