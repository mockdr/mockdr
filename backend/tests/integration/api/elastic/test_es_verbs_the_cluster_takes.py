"""The verbs Elasticsearch accepts that mockdr answered 405 to.

Measured on 8.15, both verbs against the same live index:

* `_flush`, `_refresh`, `_analyze`, `_validate/query`, `_terms_enum` and
  `_msearch` answer a GET exactly as they answer a POST — the same body,
  byte for byte — because a client may carry its query in the body of a GET;
* `_forcemerge` and `_cache/clear` do **not**, and stay POST-only.  There is
  no rule behind the split, only the measurement;
* a mapping update is accepted on `POST` as well as `PUT`, and the two do
  the same thing.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(
    b"elastic:mock-elastic-password").decode()}


def _an_index(client: TestClient) -> str:
    name = "zzz-verb-parity"
    client.put(f"/elastic/{name}/_doc/1", headers=AUTH, json={"a": 1})
    return name


class TestGetIsTheSameAsPost:
    def test_flush_and_refresh_take_a_get(self, client: TestClient) -> None:
        index = _an_index(client)
        for endpoint in ("_flush", "_refresh"):
            get = client.get(f"/elastic/{index}/{endpoint}", headers=AUTH)
            post = client.post(f"/elastic/{index}/{endpoint}", headers=AUTH)
            assert get.status_code == post.status_code == 200, endpoint
            assert get.json() == post.json(), endpoint

    def test_analyze_and_terms_enum_take_a_get(self, client: TestClient) -> None:
        index = _an_index(client)
        for endpoint, body in (("_analyze", {"text": "hello"}),
                               ("_terms_enum", {"field": "a", "string": ""})):
            get = client.request("GET", f"/elastic/{index}/{endpoint}",
                                 headers=AUTH, json=body)
            post = client.post(f"/elastic/{index}/{endpoint}",
                               headers=AUTH, json=body)
            assert get.status_code == post.status_code, endpoint
            assert get.json() == post.json(), endpoint

    def test_validate_query_takes_a_get(self, client: TestClient) -> None:
        index = _an_index(client)
        body = {"query": {"match_all": {}}}
        get = client.request("GET", f"/elastic/{index}/_validate/query",
                             headers=AUTH, json=body)
        post = client.post(f"/elastic/{index}/_validate/query",
                           headers=AUTH, json=body)
        assert get.status_code == post.status_code
        assert get.json() == post.json()

    def test_msearch_takes_a_get(self, client: TestClient) -> None:
        index = _an_index(client)
        ndjson = f'{{"index":"{index}"}}\n{{"query":{{"match_all":{{}}}}}}\n'
        headers = {**AUTH, "Content-Type": "application/x-ndjson"}
        get = client.request("GET", "/elastic/_msearch", headers=headers,
                             content=ndjson)
        post = client.post("/elastic/_msearch", headers=headers, content=ndjson)
        assert get.status_code == post.status_code == 200
        assert len(get.json()["responses"]) == len(post.json()["responses"])


class TestWhereTheSplitFalls:
    def test_forcemerge_and_cache_clear_stay_post_only(
        self, client: TestClient,
    ) -> None:
        """The cluster answers these two with a 405, unlike their neighbours."""
        index = _an_index(client)
        for endpoint in ("_forcemerge", "_cache/clear"):
            resp = client.get(f"/elastic/{index}/{endpoint}", headers=AUTH)
            assert resp.status_code == 405, endpoint


class TestMappingTakesBothVerbs:
    def test_post_updates_the_mapping_like_put(self, client: TestClient) -> None:
        index = _an_index(client)
        put = client.put(f"/elastic/{index}/_mapping", headers=AUTH,
                         json={"properties": {"f1": {"type": "keyword"}}})
        post = client.post(f"/elastic/{index}/_mapping", headers=AUTH,
                           json={"properties": {"f2": {"type": "keyword"}}})
        assert put.status_code == post.status_code == 200
        assert put.json() == post.json() == {"acknowledged": True}
        mapping = client.get(f"/elastic/{index}/_mapping", headers=AUTH).json()
        properties = mapping[index]["mappings"]["properties"]
        assert "f1" in properties and "f2" in properties


class TestDeleteWithNothingNamed:
    def test_the_root_is_the_delete_index_endpoint_with_no_index(
        self, client: TestClient,
    ) -> None:
        """`DELETE /` reaches delete-index and is told what is missing.

        A client that built its URL from an empty variable used to get a 405
        about the verb, which sends it looking in the wrong place.  Measured
        on 8.15, body for body.
        """
        resp = client.request("DELETE", "/elastic/", headers=AUTH)
        assert resp.status_code == 400
        reason = "Validation Failed: 1: index / indices is missing;"
        assert resp.json() == {
            "error": {
                "root_cause": [
                    {"type": "action_request_validation_exception",
                     "reason": reason},
                ],
                "type": "action_request_validation_exception",
                "reason": reason,
            },
            "status": 400,
        }


class TestThe405NamesWhatWasSent:
    """The cluster echoes the uri with its query string, and clients log it."""

    def test_a_wrong_verb_names_the_query_string(self, client: TestClient) -> None:
        resp = client.request("DELETE", "/elastic/zzz-idx/_search",
                              headers=AUTH, params={"size": 1})
        assert resp.status_code == 405
        assert resp.json()["error"] == (
            "Incorrect HTTP method for uri [/zzz-idx/_search?size=1] and "
            "method [DELETE], allowed: [GET, POST]"
        )

    def test_an_unknown_cat_endpoint_names_it_too(self, client: TestClient) -> None:
        resp = client.get("/elastic/_cat/zzz", headers=AUTH,
                          params={"format": "json", "v": "true"})
        assert resp.status_code == 405
        assert resp.json()["error"] == (
            "Incorrect HTTP method for uri [/_cat/zzz?format=json&v=true] and "
            "method [GET], allowed: [POST]"
        )

    def test_without_a_query_string_there_is_no_question_mark(
        self, client: TestClient,
    ) -> None:
        resp = client.request("DELETE", "/elastic/zzz-idx/_search", headers=AUTH)
        assert resp.status_code == 405
        assert "[/zzz-idx/_search]" in resp.json()["error"]
