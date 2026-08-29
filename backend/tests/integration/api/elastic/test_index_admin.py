"""Aliases, settings, multi-search, and the two ways to page past a page.

Measured against Elasticsearch 8.15. None of these were served: an alias
call was a 404, so a client that created one could not search through it; a
`_msearch` fell through to the 404 handler, which is what Kibana sends for
almost every panel; and a scrolled search came back without a scroll id, so
a fetch that works against a cluster stopped after its first page here —
with no error to say why.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
INDEX = "admin-test"


@pytest.fixture
def client() -> TestClient:
    """A client with three documents in a mapped index."""
    with TestClient(app) as test_client:
        test_client.delete(f"/elastic/{INDEX}", headers=AUTH)
        test_client.put(f"/elastic/{INDEX}", headers=AUTH, json={"mappings": {"properties": {
            "host": {"type": "keyword"}, "sev": {"type": "integer"},
            "msg": {"type": "text"},
        }}})
        for i in (1, 2, 3):
            test_client.put(
                f"/elastic/{INDEX}/_doc/{i}", headers=AUTH,
                json={"host": f"h{i}", "sev": i * 10, "msg": f"failed login {i}"},
            )
        yield test_client
        test_client.delete(f"/elastic/{INDEX}", headers=AUTH)


class TestAliases:
    """An alias is how a SIEM addresses its indices."""

    def test_an_alias_can_be_pointed_at_an_index(self, client: TestClient) -> None:
        response = client.put(f"/elastic/{INDEX}/_alias/admin-alias", headers=AUTH)
        assert response.status_code == 200
        assert response.json() == {"acknowledged": True, "errors": False}

    def test_and_the_index_reports_it(self, client: TestClient) -> None:
        client.put(f"/elastic/{INDEX}/_alias/admin-alias", headers=AUTH)
        body = client.get(f"/elastic/{INDEX}/_alias", headers=AUTH).json()
        assert body[INDEX]["aliases"] == {"admin-alias": {}}

    def test_a_search_through_the_alias_finds_the_documents(
        self, client: TestClient,
    ) -> None:
        # The point of the whole endpoint: without it the alias was a 404.
        client.put(f"/elastic/{INDEX}/_alias/admin-alias", headers=AUTH)
        body = client.post("/elastic/admin-alias/_search", headers=AUTH,
                           json={"size": 0}).json()
        assert body["hits"]["total"]["value"] == 3

    def test_the_batch_form_adds_and_removes(self, client: TestClient) -> None:
        client.post("/elastic/_aliases", headers=AUTH, json={"actions": [
            {"add": {"index": INDEX, "alias": "batch-alias"}},
        ]})
        assert "batch-alias" in client.get(
            f"/elastic/{INDEX}/_alias", headers=AUTH,
        ).json()[INDEX]["aliases"]
        client.post("/elastic/_aliases", headers=AUTH, json={"actions": [
            {"remove": {"index": INDEX, "alias": "batch-alias"}},
        ]})
        assert client.get(f"/elastic/{INDEX}/_alias", headers=AUTH).json()[INDEX][
            "aliases"
        ] == {}

    def test_an_alias_nothing_carries_is_a_404(self, client: TestClient) -> None:
        response = client.get("/elastic/_alias/no-such-alias", headers=AUTH)
        assert response.status_code == 404
        # This one endpoint answers with a plain string where every other
        # Elasticsearch error is an object.
        assert response.json()["error"] == "alias [no-such-alias] missing"

    def test_an_index_that_is_not_there_cannot_take_one(self, client: TestClient) -> None:
        assert client.put("/elastic/no-such/_alias/a", headers=AUTH).status_code == 404


class TestSettings:
    """The half of an index a client tunes."""

    def test_the_settings_come_back(self, client: TestClient) -> None:
        body = client.get(f"/elastic/{INDEX}/_settings", headers=AUTH).json()
        settings = body[INDEX]["settings"]["index"]
        assert settings["number_of_shards"] == "1"
        # One, which is a cluster's default even on a single node.
        assert settings["number_of_replicas"] == "1"

    def test_they_can_be_changed(self, client: TestClient) -> None:
        response = client.put(f"/elastic/{INDEX}/_settings", headers=AUTH,
                              json={"index": {"number_of_replicas": 2}})
        assert response.json() == {"acknowledged": True}
        body = client.get(f"/elastic/{INDEX}/_settings", headers=AUTH).json()
        assert body[INDEX]["settings"]["index"]["number_of_replicas"] == "2"

    def test_an_index_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        assert client.get("/elastic/no-such/_settings", headers=AUTH).status_code == 404


class TestMultiSearch:
    """Several searches in one request, which is how Kibana asks."""

    #: The cluster refuses a body with no `Content-Type` — 406, measured — so
    #: a client that omits it never reaches `_msearch` at all.
    NDJSON = {**AUTH, "Content-Type": "application/x-ndjson"}

    def ndjson(self, *pairs: dict) -> str:
        return "\n".join(json.dumps(p) for p in pairs) + "\n"

    def test_each_search_answers_in_order(self, client: TestClient) -> None:
        body = self.ndjson(
            {"index": INDEX}, {"query": {"match_all": {}}, "size": 0},
            {"index": INDEX}, {"query": {"term": {"host": "h1"}}, "size": 0},
        )
        response = client.post(f"/elastic/{INDEX}/_msearch", headers=self.NDJSON, content=body)
        assert response.status_code == 200
        responses = response.json()["responses"]
        assert [r["hits"]["total"]["value"] for r in responses] == [3, 1]

    def test_each_answer_carries_its_own_status(self, client: TestClient) -> None:
        body = self.ndjson({"index": INDEX}, {"query": {"match_all": {}}, "size": 0})
        responses = client.post("/elastic/_msearch", headers=self.NDJSON, content=body).json()
        assert responses["responses"][0]["status"] == 200

    def test_a_shard_failure_belongs_to_its_own_search(
        self, client: TestClient,
    ) -> None:
        body = self.ndjson(
            {"index": "no-such-index"}, {"query": {"match_all": {}}},
            {"index": INDEX}, {"query": {"match_all": {}}, "size": 0},
        )
        responses = client.post("/elastic/_msearch", headers=self.NDJSON, content=body).json()
        assert responses["responses"][0]["status"] == 404
        assert responses["responses"][1]["status"] == 200

    def test_but_a_body_that_will_not_parse_fails_the_request(
        self, client: TestClient,
    ) -> None:
        # The error is in the request, not in one of the searches.
        body = self.ndjson(
            {"index": INDEX}, {"query": {"nosuchquery": {}}},
            {"index": INDEX}, {"query": {"match_all": {}}, "size": 0},
        )
        response = client.post("/elastic/_msearch", headers=self.NDJSON, content=body)
        assert response.status_code == 400
        assert response.json()["error"]["type"] == "parsing_exception"


class TestAnalyze:
    """What a field's analyser makes of some text."""

    def tokens(self, client: TestClient, body: dict) -> list[dict]:
        return client.post(f"/elastic/{INDEX}/_analyze", headers=AUTH, json=body).json()["tokens"]

    def test_words_are_split_and_lowercased(self, client: TestClient) -> None:
        tokens = self.tokens(client, {"text": "srv-1, FAILED"})
        assert [t["token"] for t in tokens] == ["srv", "1", "failed"]

    def test_a_number_says_so(self, client: TestClient) -> None:
        tokens = self.tokens(client, {"text": "abc 42"})
        assert [t["type"] for t in tokens] == ["<ALPHANUM>", "<NUM>"]

    def test_an_address_is_one_token(self, client: TestClient) -> None:
        assert [t["token"] for t in self.tokens(client, {"text": "10.0.0.1"})] == ["10.0.0.1"]

    def test_a_keyword_field_keeps_the_whole_value(self, client: TestClient) -> None:
        tokens = self.tokens(client, {"text": "a B", "field": "host"})
        assert tokens == [{"token": "a B", "start_offset": 0, "end_offset": 3,
                           "type": "word", "position": 0}]

    def test_a_text_field_is_analysed(self, client: TestClient) -> None:
        assert len(self.tokens(client, {"text": "a B", "field": "msg"})) == 2

    def test_text_is_required(self, client: TestClient) -> None:
        response = client.post(f"/elastic/{INDEX}/_analyze", headers=AUTH, json={})
        assert response.status_code == 400
        assert response.json()["error"]["reason"] == "Validation Failed: 1: text is missing;"


class TestValidateQuery:
    """Whether a query would run, without running it."""

    def test_a_query_that_would_run(self, client: TestClient) -> None:
        body = client.post(f"/elastic/{INDEX}/_validate/query", headers=AUTH,
                           json={"query": {"term": {"host": "h1"}}}).json()
        assert body["valid"] is True
        assert body["_shards"]["successful"] == 1

    def test_one_that_would_not(self, client: TestClient) -> None:
        body = client.post(f"/elastic/{INDEX}/_validate/query", headers=AUTH,
                           json={"query": {"nosuchquery": {}}}).json()
        # No shards, and no error either: just the answer.
        assert body == {"valid": False}

    def test_explain_adds_the_reason(self, client: TestClient) -> None:
        body = client.post(f"/elastic/{INDEX}/_validate/query", headers=AUTH,
                           params={"explain": "true"},
                           json={"query": {"nosuchquery": {}}}).json()
        assert body["valid"] is False
        assert "nosuchquery" in body["error"]

    def test_a_request_with_no_query_is_refused(self, client: TestClient) -> None:
        response = client.post(f"/elastic/{INDEX}/_validate/query", headers=AUTH, json={})
        assert response.status_code == 400
        assert response.json()["error"]["reason"] == (
            "Validation Failed: 1: query cannot be null;"
        )


class TestTermsEnum:
    """The values of a field, which is what an autocomplete asks for."""

    def terms(self, client: TestClient, body: dict) -> list[str]:
        return client.post(f"/elastic/{INDEX}/_terms_enum", headers=AUTH, json=body).json()["terms"]

    def test_a_keyword_field_lists_its_values(self, client: TestClient) -> None:
        assert self.terms(client, {"field": "host"}) == ["h1", "h2", "h3"]

    def test_a_prefix_narrows_them(self, client: TestClient) -> None:
        assert self.terms(client, {"field": "host", "string": "h1"}) == ["h1"]

    def test_case_can_be_ignored(self, client: TestClient) -> None:
        terms = self.terms(client, {"field": "host", "string": "H", "case_insensitive": True})
        assert terms == ["h1", "h2", "h3"]

    def test_a_text_field_has_nothing_to_enumerate(self, client: TestClient) -> None:
        # Nor a numeric one, nor a field the mapping does not have — and none
        # of the three is an error.
        assert self.terms(client, {"field": "msg"}) == []
        assert self.terms(client, {"field": "sev"}) == []
        assert self.terms(client, {"field": "nope"}) == []


class TestScrollAndPit:
    """The two ways a client reads more than a page."""

    def test_a_scrolled_search_hands_back_an_id(self, client: TestClient) -> None:
        body = client.post(f"/elastic/{INDEX}/_search", headers=AUTH,
                           params={"scroll": "1m"},
                           json={"size": 2, "sort": [{"sev": "asc"}]}).json()
        assert body["_scroll_id"]
        assert [h["_id"] for h in body["hits"]["hits"]] == ["1", "2"]

    def test_and_the_next_page_comes_from_it(self, client: TestClient) -> None:
        first = client.post(f"/elastic/{INDEX}/_search", headers=AUTH,
                            params={"scroll": "1m"},
                            json={"size": 2, "sort": [{"sev": "asc"}]}).json()
        scroll_id = first["_scroll_id"]
        second = client.post("/elastic/_search/scroll", headers=AUTH,
                             json={"scroll": "1m", "scroll_id": scroll_id}).json()
        assert [h["_id"] for h in second["hits"]["hits"]] == ["3"]
        # The same id pages again, and running out is an empty page, not an
        # error.
        assert second["_scroll_id"] == scroll_id
        third = client.post("/elastic/_search/scroll", headers=AUTH,
                            json={"scroll": "1m", "scroll_id": scroll_id}).json()
        assert third["hits"]["hits"] == []

    def test_a_cleared_scroll_is_gone(self, client: TestClient) -> None:
        first = client.post(f"/elastic/{INDEX}/_search", headers=AUTH,
                            params={"scroll": "1m"}, json={"size": 1}).json()
        cleared = client.request("DELETE", "/elastic/_search/scroll", headers=AUTH,
                                 json={"scroll_id": first["_scroll_id"]})
        assert cleared.json() == {"succeeded": True, "num_freed": 1}
        gone = client.post("/elastic/_search/scroll", headers=AUTH,
                           json={"scroll_id": first["_scroll_id"]})
        assert gone.status_code == 404
        assert gone.json()["error"]["type"] == "search_phase_execution_exception"

    def test_a_point_in_time_pages_with_search_after(self, client: TestClient) -> None:
        pit_id = client.post(f"/elastic/{INDEX}/_pit", headers=AUTH,
                             params={"keep_alive": "1m"}).json()["id"]
        first = client.post("/elastic/_search", headers=AUTH, json={
            "size": 2, "pit": {"id": pit_id}, "sort": [{"sev": "asc"}],
        }).json()
        assert first["pit_id"] == pit_id
        # Each hit carries the `_shard_doc` tiebreaker the point in time adds,
        # so `search_after` has a unique value to page from.
        assert [h["sort"] for h in first["hits"]["hits"]] == [[10, 0], [20, 1]]
        second = client.post("/elastic/_search", headers=AUTH, json={
            "size": 2, "pit": {"id": pit_id}, "sort": [{"sev": "asc"}],
            "search_after": first["hits"]["hits"][-1]["sort"],
        }).json()
        assert [h["_id"] for h in second["hits"]["hits"]] == ["3"]

    def test_a_closed_point_in_time_is_gone(self, client: TestClient) -> None:
        pit_id = client.post(f"/elastic/{INDEX}/_pit", headers=AUTH,
                             params={"keep_alive": "1m"}).json()["id"]
        closed = client.request("DELETE", "/elastic/_pit", headers=AUTH,
                                json={"id": pit_id})
        assert closed.json() == {"succeeded": True, "num_freed": 1}
        gone = client.post("/elastic/_search", headers=AUTH, json={"pit": {"id": pit_id}})
        assert gone.status_code == 404


class TestResolveIndex:
    """What a name stands for."""

    def test_an_index_and_its_aliases(self, client: TestClient) -> None:
        client.put(f"/elastic/{INDEX}/_alias/resolve-alias", headers=AUTH)
        body = client.get(f"/elastic/_resolve/index/{INDEX}", headers=AUTH).json()
        assert body["indices"][0]["name"] == INDEX
        assert body["indices"][0]["aliases"] == ["resolve-alias"]
        assert body["indices"][0]["attributes"] == ["open"]
