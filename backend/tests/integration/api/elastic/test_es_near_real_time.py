"""A write is not searchable until a refresh, and a delete still is.

Elasticsearch is near real time: `PUT /{index}/_doc/{id}` without a refresh
answers 201 and the document is *not* in the next `_search` — though
`GET /_doc/{id}` finds it at once, because a get reads the live state and a
search reads a snapshot.  A delete is the mirror: gone to the get, still
there to the search, until a refresh.  `_bulk` obeys the same rule, and
`?refresh=true` and `?refresh=wait_for` force one for that write.

mockdr made every write searchable at once, which is the dangerous
direction: a client — or a test — that wrote and immediately searched
worked against the mock and failed against the product.  Fifteen of this
repo's own tests were doing exactly that.

Measured on 8.15, write, delete and bulk.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(
    b"elastic:mock-elastic-password").decode()}
INDEX = "/elastic/zzz-near-real-time"


def _hits(client: TestClient) -> int:
    return int(client.post(f"{INDEX}/_search", headers=AUTH,
                           json={}).json()["hits"]["total"]["value"])


class TestAWriteIsNotSearchableUntilARefresh:
    def test_the_search_does_not_see_it_but_a_get_does(
        self, client: TestClient,
    ) -> None:
        client.put(INDEX, headers=AUTH, json={})
        assert client.put(f"{INDEX}/_doc/1", headers=AUTH,
                          json={"a": 1}).status_code == 201
        assert _hits(client) == 0
        assert client.get(f"{INDEX}/_doc/1", headers=AUTH).status_code == 200

    def test_a_refresh_makes_it_searchable(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH, json={"a": 1})
        client.post(f"{INDEX}/_refresh", headers=AUTH)
        assert _hits(client) == 1

    def test_the_write_can_ask_for_one_itself(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        for value in ("true", "wait_for"):
            client.put(f"{INDEX}/_doc/{value}", headers=AUTH,
                       params={"refresh": value}, json={"a": 1})
        assert _hits(client) == 2

    def test_refresh_false_asks_for_nothing(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH,
                   params={"refresh": "false"}, json={"a": 1})
        assert _hits(client) == 0


class TestADeleteIsTheMirror:
    def test_it_is_gone_to_a_get_and_still_there_to_a_search(
        self, client: TestClient,
    ) -> None:
        client.put(INDEX, headers=AUTH, json={})
        client.put(f"{INDEX}/_doc/1", headers=AUTH,
                   params={"refresh": "true"}, json={"a": 1})
        assert _hits(client) == 1

        client.delete(f"{INDEX}/_doc/1", headers=AUTH)
        assert client.get(f"{INDEX}/_doc/1", headers=AUTH).status_code == 404
        assert _hits(client) == 1

        client.post(f"{INDEX}/_refresh", headers=AUTH)
        assert _hits(client) == 0


class TestBulkObeysTheSameRule:
    def test_nothing_it_indexes_is_searchable_until_a_refresh(
        self, client: TestClient,
    ) -> None:
        client.put(INDEX, headers=AUTH, json={})
        body = ('{"index":{"_index":"zzz-near-real-time","_id":"b"}}\n'
                '{"a":1}\n')
        client.post("/elastic/_bulk", headers={**AUTH,
                    "Content-Type": "application/x-ndjson"}, content=body)
        assert _hits(client) == 0
        client.post(f"{INDEX}/_refresh", headers=AUTH)
        assert _hits(client) == 1

    def test_and_it_can_ask_for_one(self, client: TestClient) -> None:
        client.put(INDEX, headers=AUTH, json={})
        body = ('{"index":{"_index":"zzz-near-real-time","_id":"c"}}\n'
                '{"a":1}\n')
        client.post("/elastic/_bulk", headers={**AUTH,
                    "Content-Type": "application/x-ndjson"},
                    params={"refresh": "true"}, content=body)
        assert _hits(client) == 1
