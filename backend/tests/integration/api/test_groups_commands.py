"""Integration tests for group mutation endpoints.

POST /groups              — create group
PUT  /groups/{id}         — update group (partial)
DELETE /groups/{id}       — delete group (404, 400 for default)
PUT  /groups/{id}/move-agents — move agents to group
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _first_non_default_group(client: TestClient, auth_headers: dict) -> dict:
    groups = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"]
    for g in groups:
        if not g["isDefault"]:
            return g
    raise RuntimeError("No non-default group in seed data")


def _default_group(client: TestClient, auth_headers: dict) -> dict:
    groups = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"]
    for g in groups:
        if g["isDefault"]:
            return g
    raise RuntimeError("No default group in seed data")


def _first_site_id(client: TestClient, auth_headers: dict) -> str:
    return client.get(f"{BASE}/sites", headers=auth_headers).json()["data"]["sites"][0]["id"]


# ── POST /groups ──────────────────────────────────────────────────────────────

class TestCreateGroup:
    def _create(self, client: TestClient, auth_headers: dict, **overrides) -> dict:
        site_id = _first_site_id(client, auth_headers)
        payload = {
            "name": "Test Group Beta",
            "siteId": site_id,
            "type": "static",
        } | overrides
        return client.post(f"{BASE}/groups", headers=auth_headers, json={"data": payload})

    def test_create_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = self._create(client, auth_headers)
        assert resp.status_code == 200

    def test_create_returns_data_envelope(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert "data" in body
        assert body["data"]["name"] == "Test Group Beta"

    def test_create_assigns_id(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert body["data"]["id"]

    def test_create_is_not_default(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers).json()
        assert body["data"]["isDefault"] is False

    def test_create_group_appears_in_list(self, client: TestClient, auth_headers: dict) -> None:
        gid = self._create(client, auth_headers).json()["data"]["id"]
        groups = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"]
        assert any(g["id"] == gid for g in groups)

    def test_create_requires_auth(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/groups", json={"data": {"name": "x"}})
        assert resp.status_code == 401

    def test_create_with_description(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers, description="My group").json()
        assert body["data"].get("description") == "My group"

    def test_create_pinned_type(self, client: TestClient, auth_headers: dict) -> None:
        body = self._create(client, auth_headers, type="pinned").json()
        assert body["data"]["type"] == "pinned"


# ── PUT /groups/{id} ──────────────────────────────────────────────────────────

class TestUpdateGroup:
    def test_update_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        gid = _first_non_default_group(client, auth_headers)["id"]
        resp = client.put(f"{BASE}/groups/{gid}", headers=auth_headers,
                          json={"data": {"name": "Renamed Group"}})
        assert resp.status_code == 200

    def test_update_renames_group(self, client: TestClient, auth_headers: dict) -> None:
        gid = _first_non_default_group(client, auth_headers)["id"]
        client.put(f"{BASE}/groups/{gid}", headers=auth_headers,
                   json={"data": {"name": "New Name"}})
        body = client.get(f"{BASE}/groups/{gid}", headers=auth_headers).json()
        assert body["data"]["name"] == "New Name"

    def test_update_partial_preserves_other_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        group = _first_non_default_group(client, auth_headers)
        client.put(f"{BASE}/groups/{group['id']}", headers=auth_headers,
                   json={"data": {"description": "Updated desc"}})
        after = client.get(f"{BASE}/groups/{group['id']}", headers=auth_headers).json()["data"]
        assert after["name"] == group["name"]

    def test_update_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.put(f"{BASE}/groups/does-not-exist", headers=auth_headers,
                          json={"data": {"name": "x"}})
        assert resp.status_code == 404

    def test_update_requires_auth(self, client: TestClient) -> None:
        resp = client.put(f"{BASE}/groups/any-id", json={"data": {"name": "x"}})
        assert resp.status_code == 401


# ── DELETE /groups/{id} ───────────────────────────────────────────────────────

class TestDeleteGroup:
    def test_delete_non_default_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        group = _first_non_default_group(client, auth_headers)
        resp = client.delete(f"{BASE}/groups/{group['id']}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["success"] is True

    def test_deleted_group_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        group = _first_non_default_group(client, auth_headers)
        client.delete(f"{BASE}/groups/{group['id']}", headers=auth_headers)
        resp = client.get(f"{BASE}/groups/{group['id']}", headers=auth_headers)
        assert resp.status_code == 404

    def test_delete_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.delete(f"{BASE}/groups/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404

    def test_delete_default_group_returns_400(self, client: TestClient, auth_headers: dict) -> None:
        group = _default_group(client, auth_headers)
        resp = client.delete(f"{BASE}/groups/{group['id']}", headers=auth_headers)
        assert resp.status_code == 400


# ── PUT /groups/{id}/move-agents ─────────────────────────────────────────────

class TestMoveAgents:
    def test_move_agents_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        groups = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"]
        target = groups[0]
        agents = client.get(f"{BASE}/agents", headers=auth_headers).json()["data"]
        agent_ids = [a["id"] for a in agents[:2]]
        resp = client.put(
            f"{BASE}/groups/{target['id']}/move-agents",
            headers=auth_headers,
            json={"agentIds": agent_ids},
        )
        assert resp.status_code == 200
        assert "affected" in resp.json()["data"]

    def test_move_agents_via_filter_key(self, client: TestClient, auth_headers: dict) -> None:
        groups = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"]
        target = groups[0]
        agents = client.get(f"{BASE}/agents", headers=auth_headers).json()["data"]
        agent_id = agents[0]["id"]
        resp = client.put(
            f"{BASE}/groups/{target['id']}/move-agents",
            headers=auth_headers,
            json={"filter": {"ids": [agent_id]}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] >= 1

    def test_move_agents_unknown_group_returns_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.put(
            f"{BASE}/groups/does-not-exist/move-agents",
            headers=auth_headers,
            json={"agentIds": []},
        )
        assert resp.status_code == 404

    def test_move_agents_with_invalid_agent_ids_returns_0(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        group = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"][0]
        resp = client.put(
            f"{BASE}/groups/{group['id']}/move-agents",
            headers=auth_headers,
            json={"agentIds": ["fake-agent-id"]},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 0
