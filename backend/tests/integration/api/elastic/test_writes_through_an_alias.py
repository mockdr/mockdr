"""A write goes to an index, never to the alias standing in front of it.

`_resolve_collection` returns the pattern it was handed, so
`_delete_by_query` through an alias built the store key `alias:id` — which
nothing is filed under — deleted nothing, and reported one document
deleted. Aliases are how index lifecycle works, so this is the ordinary
way a client deletes, and the answer said the work was done.

Measured on Elasticsearch 8.15: three documents behind an alias, delete one
through the alias, two remain.

Found while probing that: `POST /{index}/_doc` and
`POST|PUT /{index}/_create/{id}` were not served at all — the ordinary
ingest call, which most client libraries use when a document has no natural
key, answered `no handler found for uri`. Both measured on 8.15:

    POST /_doc          201, `_id` 20 chars of the URL-safe base64 alphabet
    PUT  /_create/k     201, then 409 version_conflict_engine_exception
                        `[k]: version conflict, document already exists
                        (current version [1])`
"""
from __future__ import annotations

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ=",
    "content-type": "application/json",
}
_REFRESH = {"refresh": "true"}


def _behind_an_alias(client: TestClient, index: str, alias: str, count: int) -> None:
    client.put(f"/elastic/{index}", headers=ES_AUTH,
               json={"mappings": {"properties": {"s": {"type": "keyword"},
                                                 "n": {"type": "long"}}}})
    client.post("/elastic/_aliases", headers=ES_AUTH, json={
        "actions": [{"add": {"index": index, "alias": alias}}]})
    for i in range(count):
        resp = client.put(f"/elastic/{index}/_doc/d{i}", headers=ES_AUTH,
                          json={"s": "x", "n": i}, params=_REFRESH)
        assert resp.status_code == 201, resp.text


def _count(client: TestClient, target: str) -> int:
    resp = client.get(f"/elastic/{target}/_count", headers=ES_AUTH)
    assert resp.status_code == 200, resp.text
    return int(resp.json()["count"])


class TestDeleteByQueryThroughAnAlias:
    def test_it_deletes_what_it_says_it_deleted(self, client: TestClient) -> None:
        _behind_an_alias(client, "probe-del-idx", "probe-del", 3)
        assert _count(client, "probe-del") == 3

        resp = client.post("/elastic/probe-del/_delete_by_query", headers=ES_AUTH,
                           params=_REFRESH, json={"query": {"term": {"n": 0}}})
        assert resp.status_code == 200, resp.text
        assert resp.json()["deleted"] == 1
        # The claim and the state, which used to disagree.
        assert _count(client, "probe-del") == 2
        assert _count(client, "probe-del-idx") == 2

    def test_the_index_itself_still_works(self, client: TestClient) -> None:
        _behind_an_alias(client, "probe-del2-idx", "probe-del2", 3)
        resp = client.post("/elastic/probe-del2-idx/_delete_by_query",
                           headers=ES_AUTH, params=_REFRESH,
                           json={"query": {"term": {"n": 1}}})
        assert resp.status_code == 200, resp.text
        assert _count(client, "probe-del2") == 2


class TestUpdateByQueryThroughAnAlias:
    def test_the_documents_actually_change(self, client: TestClient) -> None:
        _behind_an_alias(client, "probe-upd-idx", "probe-upd", 3)

        resp = client.post("/elastic/probe-upd/_update_by_query", headers=ES_AUTH,
                           params=_REFRESH, json={
                               "query": {"term": {"s": "x"}},
                               "script": {"source": "ctx._source.n = 99"}})
        assert resp.status_code == 200, resp.text
        assert resp.json()["updated"] == 3

        for i in range(3):
            got = client.get(f"/elastic/probe-upd-idx/_doc/d{i}", headers=ES_AUTH)
            assert got.status_code == 200, got.text
            assert got.json()["_source"]["n"] == 99


class TestTheOrdinaryIngestCall:
    def test_post_doc_picks_an_id_and_the_document_is_there(
        self, client: TestClient,
    ) -> None:
        client.put("/elastic/probe-auto", headers=ES_AUTH, json={})
        resp = client.post("/elastic/probe-auto/_doc", headers=ES_AUTH,
                           json={"s": "auto"}, params=_REFRESH)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["result"] == "created"
        assert len(body["_id"]) == 20

        got = client.get(f"/elastic/probe-auto/_doc/{body['_id']}", headers=ES_AUTH)
        assert got.status_code == 200, got.text
        assert got.json()["_source"] == {"s": "auto"}

    def test_two_writes_get_two_ids(self, client: TestClient) -> None:
        client.put("/elastic/probe-auto2", headers=ES_AUTH, json={})
        first = client.post("/elastic/probe-auto2/_doc", headers=ES_AUTH,
                            json={"s": "a"}, params=_REFRESH).json()["_id"]
        second = client.post("/elastic/probe-auto2/_doc", headers=ES_AUTH,
                             json={"s": "b"}, params=_REFRESH).json()["_id"]
        assert first != second
        assert _count(client, "probe-auto2") == 2


class TestCreateRefusesWhereDocReplaces:
    def test_the_second_write_is_a_conflict_and_changes_nothing(
        self, client: TestClient,
    ) -> None:
        client.put("/elastic/probe-cr", headers=ES_AUTH, json={})
        first = client.put("/elastic/probe-cr/_create/k", headers=ES_AUTH,
                           json={"s": "one"}, params=_REFRESH)
        assert first.status_code == 201, first.text

        again = client.put("/elastic/probe-cr/_create/k", headers=ES_AUTH,
                           json={"s": "two"})
        assert again.status_code == 409
        error = again.json()["error"]
        assert error["type"] == "version_conflict_engine_exception"
        assert error["reason"] == (
            "[k]: version conflict, document already exists (current version [1])")

        got = client.get("/elastic/probe-cr/_doc/k", headers=ES_AUTH)
        assert got.json()["_source"] == {"s": "one"}

    def test_doc_replaces_where_create_refuses(self, client: TestClient) -> None:
        """The difference between the two routes, stated."""
        client.put("/elastic/probe-cr2", headers=ES_AUTH, json={})
        client.put("/elastic/probe-cr2/_doc/k", headers=ES_AUTH,
                   json={"s": "one"}, params=_REFRESH)
        replaced = client.put("/elastic/probe-cr2/_doc/k", headers=ES_AUTH,
                              json={"s": "two"}, params=_REFRESH)
        assert replaced.status_code == 200, replaced.text
        got = client.get("/elastic/probe-cr2/_doc/k", headers=ES_AUTH)
        assert got.json()["_source"] == {"s": "two"}
