"""Integration tests for GET /users endpoints.

Verifies response shape, required fields, and that authentication-sensitive
internal fields (_apiToken, role, accountId, accountName) are never exposed.
"""
from fastapi.testclient import TestClient

from utils.internal_fields import USER_INTERNAL_FIELDS

_INTERNAL = USER_INTERNAL_FIELDS
_REQUIRED = {"id", "email", "fullName", "source", "lowestRole", "scope",
             "twoFaEnabled", "twoFaStatus", "dateJoined", "lastLogin"}


class TestListUsers:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/web/api/v2.1/users").status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/users", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "pagination" in body
        assert isinstance(body["data"], list)

    def test_required_fields_present(self, client: TestClient, auth_headers: dict) -> None:
        user = client.get("/web/api/v2.1/users", headers=auth_headers).json()["data"][0]
        for field in _REQUIRED:
            assert field in user, f"Required field '{field}' missing from user"

    def test_no_internal_fields(self, client: TestClient, auth_headers: dict) -> None:
        for user in client.get("/web/api/v2.1/users", headers=auth_headers).json()["data"]:
            for field in _INTERNAL:
                assert field not in user, f"Internal field '{field}' leaked in user response"

    def test_api_token_never_exposed(self, client: TestClient, auth_headers: dict) -> None:
        """_apiToken is the stored credential — it must never appear in any response."""
        for user in client.get("/web/api/v2.1/users", headers=auth_headers).json()["data"]:
            assert "_apiToken" not in user
            # The public apiToken field is always None per the S1 API contract
            assert user.get("apiToken") is None

    def test_two_fa_status_is_valid_string(self, client: TestClient, auth_headers: dict) -> None:
        user = client.get("/web/api/v2.1/users", headers=auth_headers).json()["data"][0]
        assert user["twoFaStatus"] in ("configured", "not_configured")

    def test_limit_parameter(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/users", headers=auth_headers, params={"limit": 2})
        assert len(resp.json()["data"]) <= 2


class TestLoginByApiToken:
    def test_valid_admin_token_returns_user(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/users/login/by-token", headers=auth_headers)
        assert resp.status_code == 200
        assert "data" in resp.json()
        assert "id" in resp.json()["data"]

    def test_invalid_token_returns_401(self, client: TestClient) -> None:
        headers = {"Authorization": "ApiToken not-a-real-token"}
        assert client.get("/web/api/v2.1/users/login/by-token", headers=headers).status_code == 401


BASE = "/web/api/v2.1/users"

_CREATE_BODY = {
    "email": "new.user@acmecorp.internal",
    "fullName": "New User",
    "role": "Viewer",
    "scope": "tenant",
}


class TestGetUser:
    def test_returns_200_for_known_id(self, client: TestClient, auth_headers: dict) -> None:
        uid = client.get(BASE, headers=auth_headers).json()["data"][0]["id"]
        resp = client.get(f"{BASE}/{uid}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == uid

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/999999999999999999", headers=auth_headers)
        assert resp.status_code == 404

    def test_requires_auth(self, client: TestClient, auth_headers: dict) -> None:
        uid = client.get(BASE, headers=auth_headers).json()["data"][0]["id"]
        assert client.get(f"{BASE}/{uid}").status_code == 401


class TestCreateUser:
    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY})
        assert resp.status_code == 200

    def test_response_contains_id_and_email(self, client: TestClient, auth_headers: dict) -> None:
        body = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]
        assert "id" in body
        assert body["email"] == _CREATE_BODY["email"]

    def test_api_token_exposed_at_creation(self, client: TestClient, auth_headers: dict) -> None:
        # S1 contract: apiToken only present at creation time
        body = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]
        assert "apiToken" in body
        assert body["apiToken"] is not None

    def test_no_internal_fields_in_response(self, client: TestClient, auth_headers: dict) -> None:
        body = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]
        for field in _INTERNAL:
            assert field not in body

    def test_created_user_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        uid = client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]["id"]
        ids = [u["id"] for u in client.get(BASE, headers=auth_headers).json()["data"]]
        assert uid in ids

    def test_requires_auth(self, client: TestClient) -> None:
        assert client.post(BASE, json={"data": _CREATE_BODY}).status_code == 401


class TestUpdateUser:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]["id"]

    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        resp = client.put(f"{BASE}/{uid}", headers=auth_headers,
                          json={"data": {"fullName": "Updated Name"}})
        assert resp.status_code == 200

    def test_updates_full_name(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        body = client.put(f"{BASE}/{uid}", headers=auth_headers,
                          json={"data": {"fullName": "Renamed User"}}).json()["data"]
        assert body["fullName"] == "Renamed User"

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(f"{BASE}/999999999999999999", headers=auth_headers,
                          json={"data": {"fullName": "x"}})
        assert resp.status_code == 404

    def test_requires_auth(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        assert client.put(f"{BASE}/{uid}", json={"data": {"fullName": "x"}}).status_code == 401


class TestDeleteUser:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]["id"]

    def test_returns_affected_one(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        body = client.delete(f"{BASE}/{uid}", headers=auth_headers).json()
        assert body["data"]["affected"] == 1

    def test_deleted_user_absent_from_list(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        client.delete(f"{BASE}/{uid}", headers=auth_headers)
        ids = [u["id"] for u in client.get(BASE, headers=auth_headers).json()["data"]]
        assert uid not in ids

    def test_requires_auth(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        assert client.delete(f"{BASE}/{uid}").status_code == 401


class TestBulkDeleteUsers:
    def _create(self, client: TestClient, auth_headers: dict) -> str:
        return client.post(BASE, headers=auth_headers, json={"data": _CREATE_BODY}).json()["data"]["id"]

    def test_returns_affected_count(self, client: TestClient, auth_headers: dict) -> None:
        uid = self._create(client, auth_headers)
        body = client.post(f"{BASE}/delete-users", headers=auth_headers,
                           json={"filter": {"ids": [uid]}}).json()
        assert body["data"]["affected"] == 1

    def test_unknown_ids_return_zero(self, client: TestClient, auth_headers: dict) -> None:
        body = client.post(f"{BASE}/delete-users", headers=auth_headers,
                           json={"filter": {"ids": ["999999999999999999"]}}).json()
        assert body["data"]["affected"] == 0


class TestGenerateApiToken:
    def test_returns_token_and_expiry(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(f"{BASE}/generate-api-token", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()["data"]
        assert "token" in body
        assert "expiresAt" in body

    def test_new_token_is_different_from_old(self, client: TestClient, auth_headers: dict) -> None:
        old_token = auth_headers["Authorization"].split(" ")[1]
        new_token = client.post(f"{BASE}/generate-api-token", headers=auth_headers).json()["data"]["token"]
        assert new_token != old_token

    def test_requires_auth(self, client: TestClient) -> None:
        assert client.post(f"{BASE}/generate-api-token").status_code == 401


class TestGetApiTokenDetails:
    def test_returns_token_details(self, client: TestClient, auth_headers: dict) -> None:
        uid = client.get("/web/api/v2.1/users/login/by-token", headers=auth_headers).json()["data"]["id"]
        resp = client.get(f"{BASE}/{uid}/api-token-details", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()["data"]
        assert "token" in body
        assert "expiresAt" in body

    def test_unknown_user_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/999999999999999999/api-token-details", headers=auth_headers)
        assert resp.status_code == 404

    def test_requires_auth(self, client: TestClient, auth_headers: dict) -> None:
        uid = client.get("/web/api/v2.1/users/login/by-token", headers=auth_headers).json()["data"]["id"]
        assert client.get(f"{BASE}/{uid}/api-token-details").status_code == 401
