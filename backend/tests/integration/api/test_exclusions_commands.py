"""Integration tests for exclusion and blocklist mutation endpoints.

POST   /exclusions               — create exclusion
DELETE /exclusions/{id}          — delete exclusion
GET    /restrictions             — list blocklist
POST   /restrictions             — add to blocklist
DELETE /restrictions/{id}        — remove from blocklist
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


class TestCreateExclusion:
    def test_create_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={
                "type": "path",
                "value": "/tmp/safe_file.exe",
                "osType": "windows",
                "mode": "suppress",
            },
        )
        assert resp.status_code == 200

    def test_create_returns_data_with_id(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"type": "path", "value": "/tmp/test.exe", "osType": "windows", "mode": "suppress"},
        )
        body = resp.json()
        assert "data" in body
        assert "id" in body["data"][0]

    def test_created_exclusion_appears_in_list(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.post(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"type": "path", "value": "/unique/path/abc123.exe", "osType": "linux", "mode": "suppress"},
        )
        new_id = resp.json()["data"][0]["id"]
        items = client.get(f"{BASE}/exclusions", headers=auth_headers).json()["data"]
        ids = [e["id"] for e in items]
        assert new_id in ids


class TestDeleteExclusion:
    def test_delete_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        # Create then delete
        eid = client.post(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"type": "path", "value": "/tmp/delete_me.exe", "osType": "windows", "mode": "suppress"},
        ).json()["data"][0]["id"]
        resp = client.delete(f"{BASE}/exclusions/{eid}", headers=auth_headers)
        assert resp.status_code == 200


class TestBlocklist:
    def test_list_blocklist_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/restrictions", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_blocklist_has_data_and_pagination(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        body = client.get(f"{BASE}/restrictions", headers=auth_headers).json()
        assert "data" in body
        assert "pagination" in body

    def test_create_blocklist_entry_returns_200(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.post(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={
                "value": "aabbccdd" * 8,
                "type": "black_hash",
                "osType": "windows",
            },
        )
        assert resp.status_code == 200

    def test_create_blocklist_entry_has_id(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        body = client.post(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={"value": "deadbeef" * 8, "type": "black_hash", "osType": "windows"},
        ).json()
        assert "data" in body
        assert "id" in body["data"]

    def test_delete_blocklist_entry_returns_200(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        bid = client.post(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={"value": "cafebabe" * 8, "type": "black_hash", "osType": "windows"},
        ).json()["data"]["id"]
        resp = client.delete(f"{BASE}/restrictions/{bid}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["success"] is True

    def test_delete_unknown_blocklist_entry_returns_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.delete(f"{BASE}/restrictions/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404
