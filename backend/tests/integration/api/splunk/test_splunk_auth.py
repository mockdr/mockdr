"""Integration tests for Splunk authentication endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _basic_auth(username: str = "admin", password: str = "mockdr-admin") -> dict[str, str]:
    """Build Basic Auth headers."""
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _bearer_auth(session_key: str) -> dict[str, str]:
    """Build Bearer token headers."""
    return {"Authorization": f"Bearer {session_key}"}


class TestLogin:
    """Tests for POST /services/auth/login."""

    def test_login_returns_session_key(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/auth/login",
            data={"username": "admin", "password": "mockdr-admin", "output_mode": "json"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "sessionKey" in body
        assert len(body["sessionKey"]) > 0

    def test_login_invalid_credentials(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/auth/login",
            data={"username": "admin", "password": "wrong"},
        )
        assert resp.status_code == 401

    def test_login_missing_credentials(self, client: TestClient) -> None:
        resp = client.post(f"{SPLUNK_PREFIX}/services/auth/login", data={})
        assert resp.status_code == 401

    def test_analyst_can_login(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/auth/login",
            data={"username": "analyst", "password": "mockdr-analyst"},
        )
        assert resp.status_code == 200
        assert "sessionKey" in resp.json()


class TestCurrentContext:
    """Tests for GET /services/authentication/current-context."""

    def test_returns_user_info_with_basic_auth(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authentication/current-context",
            headers=_basic_auth(),
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        assert body["entry"][0]["content"]["username"] == "admin"

    def test_returns_user_info_with_bearer(self, client: TestClient) -> None:
        # First login to get session key
        login_resp = client.post(
            f"{SPLUNK_PREFIX}/services/auth/login",
            data={"username": "admin", "password": "mockdr-admin"},
        )
        session_key = login_resp.json()["sessionKey"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authentication/current-context",
            headers=_bearer_auth(session_key),
        )
        assert resp.status_code == 200

    def test_unauthorized_without_auth(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/authentication/current-context")
        assert resp.status_code == 401


class TestUsers:
    """Tests for user listing endpoints."""

    def test_list_users(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authentication/users",
            headers=_basic_auth(),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        usernames = [e["name"] for e in body["entry"]]
        assert "admin" in usernames
        assert "analyst" in usernames
        assert "viewer" in usernames

    def test_get_user(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authentication/users/admin",
            headers=_basic_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["entry"][0]["content"]["roles"] == ["admin"]

    def test_get_nonexistent_user(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authentication/users/nonexistent",
            headers=_basic_auth(),
        )
        assert resp.status_code == 404

    def test_list_roles(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authorization/roles",
            headers=_basic_auth(),
        )
        assert resp.status_code == 200
        assert len(resp.json()["entry"]) >= 3

    def test_list_capabilities(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/authorization/capabilities",
            headers=_basic_auth(),
        )
        assert resp.status_code == 200
