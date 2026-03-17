"""Integration tests for account endpoints.

GET    /accounts           — list accounts
GET    /accounts/{id}      — get single account
POST   /accounts           — create account
PUT    /accounts/{id}      — update account (partial)
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _first_account(client: TestClient, auth_headers: dict) -> dict:
    return client.get(f"{BASE}/accounts", headers=auth_headers).json()["data"][0]


def _first_account_id(client: TestClient, auth_headers: dict) -> str:
    return _first_account(client, auth_headers)["id"]


# ── GET /accounts ─────────────────────────────────────────────────────────────

class TestListAccounts:
    def test_list_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/accounts", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_has_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(f"{BASE}/accounts", headers=auth_headers).json()
        assert "data" in body
        assert "pagination" in body

    def test_list_contains_at_least_one_account(self, client: TestClient, auth_headers: dict) -> None:
        data = client.get(f"{BASE}/accounts", headers=auth_headers).json()["data"]
        assert len(data) >= 1

    def test_account_has_expected_fields(self, client: TestClient, auth_headers: dict) -> None:
        account = _first_account(client, auth_headers)
        for field in ("id", "name", "state", "accountType", "numberOfSites", "numberOfAgents"):
            assert field in account


# ── GET /accounts/{id} ────────────────────────────────────────────────────────

class TestGetAccount:
    def test_get_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        aid = _first_account_id(client, auth_headers)
        resp = client.get(f"{BASE}/accounts/{aid}", headers=auth_headers)
        assert resp.status_code == 200

    def test_get_returns_correct_id(self, client: TestClient, auth_headers: dict) -> None:
        aid = _first_account_id(client, auth_headers)
        body = client.get(f"{BASE}/accounts/{aid}", headers=auth_headers).json()
        assert body["data"]["id"] == aid

    def test_get_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/accounts/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404


# ── POST /accounts ────────────────────────────────────────────────────────────

class TestCreateAccount:
    def _create(self, client: TestClient, auth_headers: dict, **overrides) -> dict:
        payload = {"name": "Test Account Gamma", "accountType": "Trial"} | overrides
        return client.post(f"{BASE}/accounts", headers=auth_headers, json={"data": payload})

    def test_create_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        assert self._create(client, auth_headers).status_code == 200

    def test_create_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert "data" in body
        assert body["data"]["name"] == "Test Account Gamma"

    def test_create_assigns_id(self, client: TestClient, auth_headers: dict) -> None:
        assert self._create(client, auth_headers).json()["data"]["id"]

    def test_create_sets_state_active(self, client: TestClient, auth_headers: dict) -> None:
        assert self._create(client, auth_headers).json()["data"]["state"] == "active"

    def test_create_account_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        aid = self._create(client, auth_headers).json()["data"]["id"]
        data = client.get(f"{BASE}/accounts", headers=auth_headers).json()["data"]
        assert any(a["id"] == aid for a in data)

    def test_create_requires_auth(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/accounts", json={"data": {"name": "x"}})
        assert resp.status_code == 401

    def test_create_paid_type(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers, accountType="Paid").json()
        assert body["data"]["accountType"] == "Paid"


# ── PUT /accounts/{id} ────────────────────────────────────────────────────────

class TestUpdateAccount:
    def test_update_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        aid = _first_account_id(client, auth_headers)
        resp = client.put(f"{BASE}/accounts/{aid}", headers=auth_headers,
                          json={"data": {"name": "Renamed Account"}})
        assert resp.status_code == 200

    def test_update_renames_account(self, client: TestClient, auth_headers: dict) -> None:
        aid = _first_account_id(client, auth_headers)
        client.put(f"{BASE}/accounts/{aid}", headers=auth_headers,
                   json={"data": {"name": "New Account Name"}})
        body = client.get(f"{BASE}/accounts/{aid}", headers=auth_headers).json()
        assert body["data"]["name"] == "New Account Name"

    def test_update_partial_preserves_other_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = _first_account_id(client, auth_headers)
        before = client.get(f"{BASE}/accounts/{aid}", headers=auth_headers).json()["data"]
        client.put(f"{BASE}/accounts/{aid}", headers=auth_headers,
                   json={"data": {"accountType": "Paid"}})
        after = client.get(f"{BASE}/accounts/{aid}", headers=auth_headers).json()["data"]
        assert after["name"] == before["name"]
        assert after["accountType"] == "Paid"

    def test_update_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(f"{BASE}/accounts/does-not-exist", headers=auth_headers,
                          json={"data": {"name": "x"}})
        assert resp.status_code == 404

    def test_update_requires_auth(self, client: TestClient) -> None:
        resp = client.put(f"{BASE}/accounts/any-id", json={"data": {"name": "x"}})
        assert resp.status_code == 401
