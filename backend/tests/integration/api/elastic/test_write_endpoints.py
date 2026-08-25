"""``_update``, the two by-query endpoints, and the calls around a write.

None of them were served: a client closing a signal or stamping a field got
a 404 from the mock and a write from the cluster. 28 calls measured against
Elasticsearch 8.15, down to the `noop` a change-free update reports, the
"[id]: document missing" a 404 carries, and which of `updated`/`deleted`
each by-query body has.

mockdr does not run Painless. It reads the shape a SIEM actually sends — an
assignment, a compound assignment, `remove()`, a write to `ctx.op` — and
refuses anything else rather than guessing, because a wrong answer to a
status update is worse than a refusal: the client believes the alert was
closed.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
INDEX = "write-test"


@pytest.fixture
def client() -> TestClient:
    """A client with three documents in a mapped index."""
    with TestClient(app) as test_client:
        test_client.delete(f"/elastic/{INDEX}", headers=AUTH)
        test_client.put(f"/elastic/{INDEX}", headers=AUTH, json={"mappings": {"properties": {
            "host": {"type": "keyword"}, "sev": {"type": "integer"},
            "status": {"type": "keyword"},
        }}})
        for i in (1, 2, 3):
            test_client.put(
                f"/elastic/{INDEX}/_doc/{i}", headers=AUTH,
                json={"host": f"h{i}", "sev": i * 10, "status": "open"},
            )
        yield test_client
        test_client.delete(f"/elastic/{INDEX}", headers=AUTH)


def source(client: TestClient, doc_id: str) -> dict:
    """The document's ``_source``."""
    return client.get(f"/elastic/{INDEX}/_source/{doc_id}", headers=AUTH).json()


class TestUpdate:
    """A partial document, an upsert, and a document that is not there."""

    def test_a_partial_document_is_merged(self, client: TestClient) -> None:
        response = client.post(
            f"/elastic/{INDEX}/_update/1", headers=AUTH, json={"doc": {"sev": 99}},
        )
        assert response.status_code == 200
        assert response.json()["result"] == "updated"
        assert source(client, "1") == {"host": "h1", "sev": 99, "status": "open"}

    def test_an_object_is_merged_field_by_field(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/1", headers=AUTH,
                    json={"doc": {"nested": {"a": 1}}})
        client.post(f"/elastic/{INDEX}/_update/1", headers=AUTH,
                    json={"doc": {"nested": {"b": 2}}})
        assert source(client, "1")["nested"] == {"a": 1, "b": 2}

    def test_writing_the_same_value_is_a_noop(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/1", headers=AUTH, json={"doc": {"sev": 99}})
        response = client.post(
            f"/elastic/{INDEX}/_update/1", headers=AUTH, json={"doc": {"sev": 99}},
        )
        body = response.json()
        assert body["result"] == "noop"
        # No shard did any work, and it says so.
        assert body["_shards"] == {"total": 0, "successful": 0, "failed": 0}

    def test_a_document_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        response = client.post(
            f"/elastic/{INDEX}/_update/zz", headers=AUTH, json={"doc": {"sev": 1}},
        )
        assert response.status_code == 404
        error = response.json()["error"]
        assert error["type"] == "document_missing_exception"
        assert error["reason"] == "[zz]: document missing"
        assert error["index"] == INDEX

    def test_doc_as_upsert_creates_it(self, client: TestClient) -> None:
        response = client.post(
            f"/elastic/{INDEX}/_update/new", headers=AUTH,
            json={"doc": {"sev": 1}, "doc_as_upsert": True},
        )
        assert response.status_code == 201
        assert response.json()["result"] == "created"
        assert source(client, "new") == {"sev": 1}

    def test_an_upsert_body_is_used_instead(self, client: TestClient) -> None:
        client.post(
            f"/elastic/{INDEX}/_update/new2", headers=AUTH,
            json={"doc": {"sev": 1}, "upsert": {"sev": 7, "host": "up"}},
        )
        assert source(client, "new2") == {"sev": 7, "host": "up"}


class TestScripts:
    """The Painless a SIEM writes, and what happens to the rest."""

    def test_an_assignment(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                    json={"script": {"source": "ctx._source.status = 'closed'"}})
        assert source(client, "2")["status"] == "closed"

    def test_a_parameter(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH, json={"script": {
            "source": "ctx._source.sev = params.v", "params": {"v": 42},
        }})
        assert source(client, "2")["sev"] == 42

    def test_a_compound_assignment(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                    json={"script": {"source": "ctx._source.sev += 1"}})
        assert source(client, "2")["sev"] == 21

    def test_the_bracket_spelling(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                    json={"script": {"source": "ctx._source['status'] = 'reopened'"}})
        assert source(client, "2")["status"] == "reopened"

    def test_a_nested_path_is_created(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                    json={"script": {"source": "ctx._source.signal.status = 'closed'"}})
        assert source(client, "2")["signal"] == {"status": "closed"}

    def test_remove_drops_a_field(self, client: TestClient) -> None:
        client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                    json={"script": {"source": "ctx._source.remove('status')"}})
        assert "status" not in source(client, "2")

    def test_ctx_op_noop_changes_nothing(self, client: TestClient) -> None:
        response = client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                               json={"script": {"source": "ctx.op = 'noop'"}})
        assert response.json()["result"] == "noop"

    def test_a_script_mockdr_cannot_read_is_refused(self, client: TestClient) -> None:
        response = client.post(f"/elastic/{INDEX}/_update/2", headers=AUTH,
                               json={"script": {"source": "for (a : b) { c() }"}})
        assert response.status_code == 400
        assert response.json()["error"]["type"] == "illegal_argument_exception"


class TestByQuery:
    """Writing or deleting everything a query matches."""

    def test_update_by_query_applies_the_script(self, client: TestClient) -> None:
        response = client.post(f"/elastic/{INDEX}/_update_by_query", headers=AUTH, json={
            "query": {"term": {"status": "open"}},
            "script": {"source": "ctx._source.status = 'closed'"},
        })
        body = response.json()
        assert (body["total"], body["updated"], body["deleted"]) == (3, 3, 0)
        assert source(client, "1")["status"] == "closed"

    def test_a_query_that_matches_nothing_writes_nothing(self, client: TestClient) -> None:
        body = client.post(f"/elastic/{INDEX}/_update_by_query", headers=AUTH, json={
            "query": {"term": {"host": "nope"}},
            "script": {"source": "ctx._source.status = 'x'"},
        }).json()
        assert (body["total"], body["updated"], body["batches"]) == (0, 0, 0)

    def test_delete_by_query_deletes(self, client: TestClient) -> None:
        body = client.post(f"/elastic/{INDEX}/_delete_by_query", headers=AUTH, json={
            "query": {"term": {"host": "h3"}},
        }).json()
        assert body["deleted"] == 1
        # And `_delete_by_query` carries no `updated` member at all.
        assert "updated" not in body
        assert client.get(f"/elastic/{INDEX}/_count", headers=AUTH).json()["count"] == 2

    def test_a_signals_status_write_reaches_the_alert(self, client: TestClient) -> None:
        # The write a SIEM actually makes: mockdr serves that collection from
        # its own repository, and a status assignment goes through it.
        body = client.post(
            "/elastic/.siem-signals-default/_update_by_query", headers=AUTH, json={
                "query": {"match_all": {}},
                "script": {"source": "ctx._source.kibana.alert.workflow_status = 'closed'"},
            },
        ).json()
        assert body["updated"] >= 1
        assert body["failures"] == []

    def test_a_write_it_cannot_make_is_reported_as_a_failure(
        self, client: TestClient,
    ) -> None:
        # Not silently counted as written: the client is told which documents
        # mockdr could not change and why.
        body = client.post(
            "/elastic/.siem-signals-default/_update_by_query", headers=AUTH, json={
                "query": {"match_all": {}},
                "script": {"source": "ctx._source.host.name = 'renamed'"},
            },
        ).json()
        assert body["updated"] == 0
        assert body["failures"][0]["cause"]["type"] == "illegal_argument_exception"


class TestAroundAWrite:
    """The maintenance calls a client makes after writing."""

    @pytest.mark.parametrize("path", ["_refresh", "_flush", "_forcemerge", "_cache/clear"])
    def test_they_are_acknowledged(self, client: TestClient, path: str) -> None:
        response = client.post(f"/elastic/{INDEX}/{path}", headers=AUTH)
        assert response.status_code == 200
        assert response.json() == {"_shards": {"total": 2, "successful": 1, "failed": 0}}

    def test_an_index_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        assert client.post("/elastic/no-such-index/_refresh", headers=AUTH).status_code == 404

    def test_the_source_of_a_document_in_an_index_that_is_not_there(
        self, client: TestClient,
    ) -> None:
        # Found by the hostile probe as a plain-text 500: the index check
        # raised out of the handler instead of answering 404.
        response = client.get("/elastic/no-such-index/_source/abc", headers=AUTH)
        assert response.status_code == 404
        assert response.json()["error"]["type"] == "index_not_found_exception"

    def test_the_source_of_a_document_that_is_not_there(self, client: TestClient) -> None:
        response = client.get(f"/elastic/{INDEX}/_source/zz", headers=AUTH)
        assert response.status_code == 404
        assert response.json()["error"]["reason"] == (
            f"Document not found [{INDEX}]/[zz]"
        )
