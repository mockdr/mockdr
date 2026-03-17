"""Integration tests for Splunk KV Store endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestKVStoreCollections:
    """Tests for KV Store collection CRUD."""

    def test_list_collections(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config",
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert "entry" in resp.json()

    def test_create_collection(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config",
            json={"name": "test_collection"},
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "test_collection"

    def test_delete_collection(self, client: TestClient) -> None:
        # Create first
        client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config",
            json={"name": "to_delete"},
            headers=_auth(),
        )
        resp = client.delete(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config/to_delete",
            headers=_auth(),
        )
        assert resp.status_code == 200


class TestKVStoreRecords:
    """Tests for KV Store record CRUD."""

    def _setup_collection(self, client: TestClient) -> None:
        client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config",
            json={"name": "test_records"},
            headers=_auth(),
        )

    def test_insert_and_get_record(self, client: TestClient) -> None:
        self._setup_collection(client)
        insert_resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            json={"field1": "value1", "field2": 42},
            headers=_auth(),
        )
        assert insert_resp.status_code == 200
        key = insert_resp.json()["_key"]

        get_resp = client.get(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records/{key}",
            headers=_auth(),
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["field1"] == "value1"

    def test_get_all_records(self, client: TestClient) -> None:
        self._setup_collection(client)
        client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            json={"name": "record1"},
            headers=_auth(),
        )
        resp = client.get(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
        assert len(resp.json()) >= 1

    def test_update_record(self, client: TestClient) -> None:
        self._setup_collection(client)
        insert_resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            json={"name": "original"},
            headers=_auth(),
        )
        key = insert_resp.json()["_key"]

        update_resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records/{key}",
            json={"name": "updated"},
            headers=_auth(),
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "updated"

    def test_delete_record(self, client: TestClient) -> None:
        self._setup_collection(client)
        insert_resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            json={"name": "to_delete"},
            headers=_auth(),
        )
        key = insert_resp.json()["_key"]

        del_resp = client.delete(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records/{key}",
            headers=_auth(),
        )
        assert del_resp.status_code == 200

    def test_batch_save(self, client: TestClient) -> None:
        self._setup_collection(client)
        resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records/batch_save",
            json=[
                {"name": "batch1"},
                {"name": "batch2"},
                {"name": "batch3"},
            ],
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    def test_delete_all_records(self, client: TestClient) -> None:
        self._setup_collection(client)
        client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            json={"name": "item"},
            headers=_auth(),
        )
        resp = client.delete(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/test_records",
            headers=_auth(),
        )
        assert resp.status_code == 200
