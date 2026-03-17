"""Integration tests for GET /exclusions endpoints.

Verifies response shape, required fields, internal field exclusion,
and OS-type / type-based filters.
"""
from fastapi.testclient import TestClient

from utils.internal_fields import EXCLUSION_INTERNAL_FIELDS

_INTERNAL = EXCLUSION_INTERNAL_FIELDS
_REQUIRED = {"id", "type", "value", "osType", "mode", "source", "createdAt", "updatedAt",
             "userId", "userName", "scopeName", "scopePath"}


class TestListExclusions:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/exclusions").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/exclusions", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        excl = client.get("/web/api/v2.1/exclusions", headers=auth_headers).json()["data"][0]
        for field in _REQUIRED:
            assert field in excl, f"Required field '{field}' missing from exclusion"

    def test_no_internal_fields(self, client: TestClient, auth_headers: dict) -> None:
        for excl in client.get("/web/api/v2.1/exclusions", headers=auth_headers).json()["data"]:
            for field in _INTERNAL:
                assert field not in excl, f"Internal field '{field}' leaked in exclusion response"

    def test_os_type_is_valid(self, client: TestClient, auth_headers: dict) -> None:
        # "any" is a valid S1 exclusion scope (applies to all OS types)
        valid_os = {"windows", "windows_legacy", "macos", "linux", "any"}
        excl = client.get("/web/api/v2.1/exclusions", headers=auth_headers).json()["data"][0]
        assert excl["osType"] in valid_os

    def test_filter_by_os_type(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/exclusions", headers=auth_headers,
                          params={"osTypes": "windows"})
        assert resp.status_code == 200
        for excl in resp.json()["data"]:
            assert excl["osType"] == "windows"

    def test_filter_by_type(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/exclusions", headers=auth_headers,
                          params={"types": "path"})
        assert resp.status_code == 200
        for excl in resp.json()["data"]:
            assert excl["type"] == "path"

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/exclusions", headers=auth_headers, params={"limit": 3})
        assert len(resp.json()["data"]) <= 3

    def test_pagination_cursor(self, client: TestClient, auth_headers: dict) -> None:
        r1 = client.get("/web/api/v2.1/exclusions", headers=auth_headers, params={"limit": 5})
        cursor = r1.json()["pagination"]["nextCursor"]
        if cursor:
            r2 = client.get("/web/api/v2.1/exclusions", headers=auth_headers,
                            params={"limit": 5, "cursor": cursor})
            assert r2.status_code == 200
            ids1 = {e["id"] for e in r1.json()["data"]}
            ids2 = {e["id"] for e in r2.json()["data"]}
            assert ids1.isdisjoint(ids2), "Cursor pagination returned overlapping results"


