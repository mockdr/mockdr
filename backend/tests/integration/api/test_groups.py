"""Integration tests for GET /groups endpoints.

Verifies response shape, required fields, internal field exclusion,
and filter/pagination behaviour.
"""
from fastapi.testclient import TestClient

from utils.internal_fields import GROUP_INTERNAL_FIELDS

_INTERNAL = GROUP_INTERNAL_FIELDS
_REQUIRED = {"id", "name", "siteId", "type", "totalAgents", "createdAt", "isDefault"}


class TestListGroups:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/groups").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/groups", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        group = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"][0]
        for field in _REQUIRED:
            assert field in group, f"Required field '{field}' missing from group"

    def test_no_internal_fields(self, client: TestClient, auth_headers: dict) -> None:
        for group in client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"]:
            for field in _INTERNAL:
                assert field not in group, f"Internal field '{field}' leaked in group response"

    def test_total_agents_is_int(self, client: TestClient, auth_headers: dict) -> None:
        group = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"][0]
        assert isinstance(group["totalAgents"], int)

    def test_filter_by_site_id(self, client: TestClient, auth_headers: dict) -> None:
        groups = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"]
        site_id = groups[0]["siteId"]
        resp = client.get("/web/api/v2.1/groups", headers=auth_headers,
                          params={"siteIds": site_id})
        assert resp.status_code == 200
        for g in resp.json()["data"]:
            assert g["siteId"] == site_id

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/groups", headers=auth_headers, params={"limit": 2})
        assert len(resp.json()["data"]) <= 2

    def test_pagination_cursor(self, client: TestClient, auth_headers: dict) -> None:
        r1 = client.get("/web/api/v2.1/groups", headers=auth_headers, params={"limit": 3})
        cursor = r1.json()["pagination"]["nextCursor"]
        if cursor:
            r2 = client.get("/web/api/v2.1/groups", headers=auth_headers,
                            params={"limit": 3, "cursor": cursor})
            assert r2.status_code == 200
            ids1 = {g["id"] for g in r1.json()["data"]}
            ids2 = {g["id"] for g in r2.json()["data"]}
            assert ids1.isdisjoint(ids2), "Cursor pagination returned overlapping results"


class TestGetGroup:
    def test_returns_single_group(self, client: TestClient, auth_headers: dict) -> None:
        gid = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"][0]["id"]
        resp = client.get(f"/web/api/v2.1/groups/{gid}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == gid

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        assert client.get("/web/api/v2.1/groups/does-not-exist", headers=auth_headers).status_code == 404

    def test_no_internal_fields_in_single(self, client: TestClient, auth_headers: dict) -> None:
        gid = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"][0]["id"]
        group = client.get(f"/web/api/v2.1/groups/{gid}", headers=auth_headers).json()["data"]
        for field in _INTERNAL:
            assert field not in group
