"""Creating an index, writing to it, and searching what was written.

Measured against Elasticsearch 8.15: the same 27 calls against both engines.
Three of them used to fail here in ways a client only discovers in
production — an index it just created answered 404, a document it indexed was
readable by id and invisible to every search, and `HEAD /{index}`, which is
how every client asks whether an index exists, answered 405.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
INDEX = "/elastic/lifecycle-test"


@pytest.fixture
def client() -> TestClient:
    """A client against the seeded app, with the test index removed after."""
    with TestClient(app) as test_client:
        test_client.delete(INDEX, headers=AUTH)
        yield test_client
        test_client.delete(INDEX, headers=AUTH)


class TestIndexLifecycle:
    """Create, describe, delete."""

    def test_an_absent_index_is_not_there(self, client: TestClient) -> None:
        assert client.head(INDEX, headers=AUTH).status_code == 404
        assert client.get(INDEX, headers=AUTH).status_code == 404

    def test_creating_one_acknowledges_it(self, client: TestClient) -> None:
        response = client.put(INDEX, headers=AUTH, json={"settings": {}})
        assert response.status_code == 200
        assert response.json() == {
            "acknowledged": True, "shards_acknowledged": True,
            "index": "lifecycle-test",
        }

    def test_a_created_index_can_then_be_searched(self, client: TestClient) -> None:
        # It answered 404 — the mock acknowledged a create it did not record.
        client.put(INDEX, headers=AUTH, json={})
        response = client.post(f"{INDEX}/_search", headers=AUTH, json={"size": 0})
        assert response.status_code == 200
        assert response.json()["hits"]["total"] == {"value": 0, "relation": "eq"}

    def test_head_answers_from_the_same_place_as_get(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        assert client.head(INDEX, headers=AUTH).status_code == 200
        assert client.head(INDEX, headers=AUTH).content == b""

    def test_the_description_reports_settings_as_strings(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={"settings": {"number_of_shards": 3}})
        settings = client.get(INDEX, headers=AUTH).json()["lifecycle-test"]["settings"]
        assert settings["index"]["number_of_shards"] == "3"
        assert settings["index"]["provided_name"] == "lifecycle-test"

    def test_creating_it_twice_is_refused(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        response = client.put(INDEX, headers=AUTH, json={})
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["type"] == "resource_already_exists_exception"
        assert error["index"] == "lifecycle-test"

    def test_deleting_it_takes_the_documents_with_it(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"a": 1})
        assert client.delete(INDEX, headers=AUTH).json() == {"acknowledged": True}
        assert client.post(f"{INDEX}/_search", headers=AUTH, json={}).status_code == 404

    def test_deleting_an_absent_index_is_a_404(self, client: TestClient) -> None:
        assert client.delete(INDEX, headers=AUTH).status_code == 404


class TestWrittenDocuments:
    """What is written is what is found."""

    def test_a_written_document_is_searchable(self, client: TestClient) -> None:
        # It was readable by id and invisible to every search: an ingest that
        # looks like it worked and a dashboard that stays empty.
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"host": "srv-1", "sev": 7})
        hits = client.post(f"{INDEX}/_search", headers=AUTH, json={"size": 5}).json()["hits"]
        assert hits["total"]["value"] == 1
        assert hits["hits"][0]["_source"] == {"host": "srv-1", "sev": 7}

    def test_a_query_filters_written_documents(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"host": "srv-1"})
        client.put(f"{INDEX}/_doc/2", headers=AUTH, params={"refresh": "true"}, json={"host": "srv-2"})
        body = {"size": 5, "query": {"term": {"host": "srv-2"}}}
        hits = client.post(f"{INDEX}/_search", headers=AUTH, json=body).json()["hits"]
        assert hits["total"]["value"] == 1

    def test_count_sees_them_too(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"a": 1})
        assert client.post(f"{INDEX}/_count", headers=AUTH, json={}).json()["count"] == 1

    def test_a_deleted_document_leaves_the_search(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"a": 1})
        # A delete needs the refresh as much as a write does: without one the
        # document is gone to a get and still there to a search.
        client.delete(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"})
        total = client.post(f"{INDEX}/_search", headers=AUTH, json={}).json()["hits"]["total"]
        assert total["value"] == 0

    def test_writing_creates_the_index(self, client: TestClient) -> None:
        # Elasticsearch creates an index on first write.
        client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"a": 1})
        assert client.head(INDEX, headers=AUTH).status_code == 200

    def test_a_create_is_201_and_a_replacement_200(self, client: TestClient) -> None:
        # How a client tells the two apart without reading the body.
        assert client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"a": 1}).status_code == 201
        assert client.put(f"{INDEX}/_doc/1", headers=AUTH, params={"refresh": "true"}, json={"a": 2}).status_code == 200


class TestRefreshParameter:
    """``refresh`` says when the write becomes visible, and is reported back."""

    @pytest.mark.parametrize(("query", "forced"), [
        ("", False),
        ("?refresh=true", True),
        ("?refresh", True),
        ("?refresh=false", False),
        ("?refresh=wait_for", False),
    ])
    def test_forced_refresh_is_echoed_only_when_it_was(
        self, client: TestClient, query: str, forced: bool,
    ) -> None:
        body = client.put(f"{INDEX}/_doc/1{query}", headers=AUTH, json={"a": 1}).json()
        assert body.get("forced_refresh", False) is forced

    def test_a_value_elasticsearch_does_not_take_is_refused(
        self, client: TestClient,
    ) -> None:
        response = client.put(f"{INDEX}/_doc/1?refresh=nonsense", headers=AUTH, json={})
        assert response.status_code == 400
        assert response.json()["error"]["reason"] == "Unknown value for refresh: [nonsense]."
