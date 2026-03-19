"""Integration tests for GET /sites — verifies real S1 allSites+sites wrapper format."""
from fastapi.testclient import TestClient

from utils.internal_fields import SITE_INTERNAL_FIELDS


class TestListSites:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/sites").status_code == 401

    def test_returns_allsites_wrapper(self, client: TestClient, auth_headers: dict) -> None:
        """Real S1 API wraps sites as data.allSites + data.sites, not a flat list."""
        body = client.get("/web/api/v2.1/sites", headers=auth_headers).json()
        assert "data" in body
        assert "allSites" in body["data"], "Missing allSites aggregate"
        assert "sites" in body["data"], "Missing sites list"
        assert isinstance(body["data"]["sites"], list)

    def test_allsites_contains_license_aggregate(self, client: TestClient, auth_headers: dict) -> None:
        all_sites = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["allSites"]
        for key in ("activeLicenses", "totalLicenses"):
            assert key in all_sites

    def test_no_internal_fields(self, client: TestClient, auth_headers: dict) -> None:
        sites = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"]
        for site in sites:
            for field in SITE_INTERNAL_FIELDS:
                assert field not in site

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        site = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"][0]
        for field in ("id", "name", "accountId", "state", "activeLicenses", "totalLicenses"):
            assert field in site


class TestGetSite:
    def test_returns_single_site(self, client: TestClient, auth_headers: dict) -> None:
        sid = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"][0]["id"]
        resp = client.get(f"/web/api/v2.1/sites/{sid}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == sid

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        assert client.get("/web/api/v2.1/sites/nope", headers=auth_headers).status_code == 404
