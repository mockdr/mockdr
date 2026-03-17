"""Integration tests for site mutation endpoints.

POST   /sites              — create site
PUT    /sites/{id}         — update site (partial)
DELETE /sites/{id}         — delete site
PUT    /sites/{id}/reactivate   — reactivate an expired/decommissioned site
POST   /sites/{id}/expire-now   — immediately expire a trial site
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _first_site(client: TestClient, auth_headers: dict) -> dict:
    return client.get(f"{BASE}/sites", headers=auth_headers).json()["data"]["sites"][0]


def _first_site_id(client: TestClient, auth_headers: dict) -> str:
    return _first_site(client, auth_headers)["id"]


def _first_account_id(client: TestClient, auth_headers: dict) -> str:
    return _first_site(client, auth_headers)["accountId"]


# ── POST /sites ───────────────────────────────────────────────────────────────

class TestCreateSite:
    def _create(self, client: TestClient, auth_headers: dict, **overrides) -> dict:
        account_id = _first_account_id(client, auth_headers)
        payload = {
            "name": "Test Site Alpha",
            "accountId": account_id,
            "siteType": "Paid",
            "suite": "Complete",
            "sku": "Complete",
            "totalLicenses": 50,
        } | overrides
        return client.post(f"{BASE}/sites", headers=auth_headers, json={"data": payload})

    def test_create_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = self._create(client, auth_headers)
        assert resp.status_code == 200

    def test_create_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert "data" in body
        assert body["data"]["name"] == "Test Site Alpha"

    def test_create_assigns_id(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert body["data"]["id"]

    def test_create_sets_state_active(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert body["data"]["state"] == "active"

    def test_create_site_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        site_id = self._create(client, auth_headers).json()["data"]["id"]
        sites = client.get(f"{BASE}/sites", headers=auth_headers).json()["data"]["sites"]
        assert any(s["id"] == site_id for s in sites)

    def test_create_requires_auth(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/sites", json={"data": {"name": "x"}})
        assert resp.status_code == 401

    def test_create_with_description(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers, description="My description").json()
        assert body["data"].get("description") == "My description"

    def test_create_sets_total_licenses(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers, totalLicenses=200).json()
        assert body["data"]["totalLicenses"] == 200


# ── PUT /sites/{id} ───────────────────────────────────────────────────────────

class TestUpdateSite:
    def test_update_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        resp = client.put(f"{BASE}/sites/{sid}", headers=auth_headers,
                          json={"data": {"name": "Renamed"}})
        assert resp.status_code == 200

    def test_update_renames_site(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        client.put(f"{BASE}/sites/{sid}", headers=auth_headers,
                   json={"data": {"name": "Updated Name"}})
        body = client.get(f"{BASE}/sites/{sid}", headers=auth_headers).json()
        assert body["data"]["name"] == "Updated Name"

    def test_update_partial_does_not_wipe_other_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        sid = _first_site_id(client, auth_headers)
        before = client.get(f"{BASE}/sites/{sid}", headers=auth_headers).json()["data"]
        client.put(f"{BASE}/sites/{sid}", headers=auth_headers,
                   json={"data": {"totalLicenses": 999}})
        after = client.get(f"{BASE}/sites/{sid}", headers=auth_headers).json()["data"]
        assert after["name"] == before["name"]
        assert after["totalLicenses"] == 999

    def test_update_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(f"{BASE}/sites/does-not-exist", headers=auth_headers,
                          json={"data": {"name": "x"}})
        assert resp.status_code == 404

    def test_update_requires_auth(self, client: TestClient) -> None:
        resp = client.put(f"{BASE}/sites/any-id", json={"data": {"name": "x"}})
        assert resp.status_code == 401


# ── DELETE /sites/{id} ────────────────────────────────────────────────────────

class TestDeleteSite:
    def _create_site(self, client: TestClient, auth_headers: dict) -> str:
        account_id = _first_account_id(client, auth_headers)
        body = client.post(f"{BASE}/sites", headers=auth_headers, json={"data": {
            "name": "Temp Site",
            "accountId": account_id,
            "siteType": "Trial",
            "suite": "Core",
            "sku": "Control",
            "totalLicenses": 10,
        }}).json()
        return body["data"]["id"]

    def test_delete_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        sid = self._create_site(client, auth_headers)
        resp = client.delete(f"{BASE}/sites/{sid}", headers=auth_headers)
        assert resp.status_code == 200

    def test_delete_returns_success_true(self, client: TestClient, auth_headers: dict) -> None:
        sid = self._create_site(client, auth_headers)
        body = client.delete(f"{BASE}/sites/{sid}", headers=auth_headers).json()
        assert body["data"]["success"] is True

    def test_deleted_site_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        sid = self._create_site(client, auth_headers)
        client.delete(f"{BASE}/sites/{sid}", headers=auth_headers)
        resp = client.get(f"{BASE}/sites/{sid}", headers=auth_headers)
        assert resp.status_code == 404

    def test_delete_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.delete(f"{BASE}/sites/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404

    def test_delete_requires_auth(self, client: TestClient) -> None:
        resp = client.delete(f"{BASE}/sites/any-id")
        assert resp.status_code == 401


# ── PUT /sites/{id}/reactivate ────────────────────────────────────────────────

class TestReactivateSite:
    def test_reactivate_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        resp = client.put(f"{BASE}/sites/{sid}/reactivate", headers=auth_headers)
        assert resp.status_code == 200

    def test_reactivate_sets_state_active(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        client.post(f"{BASE}/sites/{sid}/expire-now", headers=auth_headers)
        body = client.put(f"{BASE}/sites/{sid}/reactivate", headers=auth_headers).json()
        assert body["data"]["state"] == "active"

    def test_reactivate_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(f"{BASE}/sites/does-not-exist/reactivate", headers=auth_headers)
        assert resp.status_code == 404

    def test_reactivate_returns_site_data(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        body = client.put(f"{BASE}/sites/{sid}/reactivate", headers=auth_headers).json()
        assert "data" in body
        assert body["data"]["id"] == sid


# ── POST /sites/{id}/expire-now ───────────────────────────────────────────────

class TestExpireSite:
    def test_expire_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        resp = client.post(f"{BASE}/sites/{sid}/expire-now", headers=auth_headers)
        assert resp.status_code == 200

    def test_expire_returns_site_object(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        body = client.post(f"{BASE}/sites/{sid}/expire-now", headers=auth_headers).json()
        assert "id" in body["data"]
        assert body["data"]["state"] == "expired"

    def test_expire_sets_state_expired(self, client: TestClient, auth_headers: dict) -> None:
        sid = _first_site_id(client, auth_headers)
        client.post(f"{BASE}/sites/{sid}/expire-now", headers=auth_headers)
        site = client.get(f"{BASE}/sites/{sid}", headers=auth_headers).json()["data"]
        assert site["state"] == "expired"

    def test_expire_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/sites/does-not-exist/expire-now", headers=auth_headers)
        assert resp.status_code == 404
