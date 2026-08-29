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


class TestScrollTakesItsIdEitherWay:
    """`_search/scroll` reads the id from the query as readily as the body.

    The route declared `scroll_id` as a query member and then read only the
    body, so a client scrolling the documented way was told its perfectly
    good id could not be parsed.  And naming no id at all is a *validation*
    failure, which on 8.15 runs before the security layer: 400, where an id
    that is present but unparsable is a 403.  Both measured against the
    cluster, id absent, in the query, and in the body.
    """

    def _a_scroll_id(self, client: TestClient) -> str:
        started = client.post(
            "/elastic/logs-endpoint/_search", headers=AUTH,
            params={"scroll": "1m"}, json={"size": 1, "query": {"match_all": {}}},
        )
        return str(started.json()["_scroll_id"])

    def test_no_id_at_all_is_a_validation_failure(self, client: TestClient) -> None:
        resp = client.request("GET", "/elastic/_search/scroll", headers=AUTH)
        assert resp.status_code == 400
        reason = "Validation Failed: 1: scrollId is missing;"
        assert resp.json() == {
            "error": {
                "root_cause": [
                    {"type": "action_request_validation_exception", "reason": reason},
                ],
                "type": "action_request_validation_exception",
                "reason": reason,
            },
            "status": 400,
        }

    def test_the_query_member_scrolls_like_the_body(self, client: TestClient) -> None:
        scroll_id = self._a_scroll_id(client)
        by_query = client.request("GET", "/elastic/_search/scroll", headers=AUTH,
                                  params={"scroll_id": scroll_id})
        assert by_query.status_code == 200, by_query.text
        assert by_query.json()["hits"]["hits"]

        scroll_id = self._a_scroll_id(client)
        by_body = client.request("GET", "/elastic/_search/scroll", headers=AUTH,
                                 json={"scroll_id": scroll_id})
        assert by_body.status_code == 200
        assert by_body.json()["hits"]["hits"]

    def test_an_id_that_cannot_be_parsed_is_still_the_403(
        self, client: TestClient,
    ) -> None:
        """Present but unparsable is refused in the security layer, not here."""
        resp = client.request("GET", "/elastic/_search/scroll", headers=AUTH,
                              params={"scroll_id": "zzz"})
        assert resp.status_code == 403
        assert resp.json()["error"]["type"] == "security_exception"


class TestABodyUnderAContentTypeTheClusterCannotRead:
    """Elasticsearch refuses the *header*, with 406 and not the 415 one guesses.

    Measured on 8.15 type by type.  It reads six of them; anything else is
    `{"error": "Content-Type header [X] is not supported", "status": 406}` —
    the bare-string error shape it also uses for a 405.  The check is made
    only when there is a body: a GET with none, or a POST with an empty one,
    is served whatever the header says.  mockdr read every body as JSON and
    answered a `parsing_exception` — a 400 about the content, where the
    product refuses the header, which sends a client that forgot
    `Content-Type` looking at its query.
    """

    BODY = '{"query":{"match_all":{}}}'

    def _search(self, client: TestClient, content_type: str, body: str = BODY):
        return client.post(
            "/elastic/logs-endpoint/_search",
            headers={**AUTH, "Content-Type": content_type}, content=body,
        )

    def test_the_six_it_reads(self, client: TestClient) -> None:
        for content_type in ("application/json", "application/json; charset=utf-8",
                             "application/JSON", "application/yaml",
                             "application/cbor", "application/smile",
                             "application/x-ndjson",
                             "application/vnd.elasticsearch+json"):
            resp = self._search(client, content_type)
            assert resp.status_code == 200, content_type

    def test_anything_else_is_406_naming_the_header(self, client: TestClient) -> None:
        for content_type in ("text/plain", "text/json", "application/json5",
                             "application/x-www-form-urlencoded", "*/*"):
            resp = self._search(client, content_type)
            assert resp.status_code == 406, content_type
            assert resp.json() == {
                "error": f"Content-Type header [{content_type}] is not supported",
                "status": 406,
            }, content_type

    def test_no_body_is_never_refused(self, client: TestClient) -> None:
        """The header is only judged when something was sent under it."""
        by_get = client.get("/elastic/logs-endpoint/_count",
                            headers={**AUTH, "Content-Type": "text/plain"})
        assert by_get.status_code == 200
        empty = self._search(client, "text/plain", body="")
        assert empty.status_code == 200


class TestUriParametersTheClusterReadsBeforeTheBody:
    """A uri parameter fails as an `illegal_argument_exception`, not a parse.

    The reason text was already right; the *type* was `parsing_exception`,
    which is what a malformed body carries.  A uri parameter is read before
    the body is parsed at all, and a client branching on the type saw a body
    error for a query it had not got wrong.

    And a time value is a number and one of seven units — `nanos`, `micros`,
    `ms`, `s`, `m`, `h`, `d`.  `w` and `y` are not among them here, though
    other parts of the stack take them, and a bare number is not one either.
    mockdr took anything at all.  Measured on 8.15 unit by unit.
    """

    def _search(self, client: TestClient, query: str):
        return client.get(f"/elastic/logs-endpoint/_search?{query}", headers=AUTH)

    def test_an_int_parameter_fails_as_an_illegal_argument(
        self, client: TestClient,
    ) -> None:
        for name in ("size", "from", "terminate_after"):
            resp = self._search(client, f"{name}=")
            assert resp.status_code == 400, name
            error = resp.json()["error"]
            assert error["type"] == "illegal_argument_exception", name
            assert error["reason"] == (
                f"Failed to parse int parameter [{name}] with value []"
            ), name

    def test_the_seven_units_are_taken(self, client: TestClient) -> None:
        for unit in ("nanos", "micros", "ms", "s", "m", "h", "d"):
            assert self._search(client, f"timeout=5{unit}").status_code == 200, unit

    def test_a_negative_time_is_still_a_time(self, client: TestClient) -> None:
        assert self._search(client, "timeout=-1s").status_code == 200

    def test_anything_else_is_a_unit_that_is_missing_or_unrecognised(
        self, client: TestClient,
    ) -> None:
        for value in ("", "5", "abc", "5x", "5w", "5y"):
            resp = self._search(client, f"timeout={value}")
            assert resp.status_code == 400, value
            error = resp.json()["error"]
            assert error["type"] == "illegal_argument_exception", value
            assert error["reason"] == (
                f"failed to parse setting [timeout] with value [{value}] "
                f"as a time value: unit is missing or unrecognized"
            ), value

    def test_scroll_is_a_time_value_too(self, client: TestClient) -> None:
        assert self._search(client, "scroll=1m").status_code == 200
        resp = self._search(client, "scroll=abc")
        assert resp.status_code == 400
        assert resp.json()["error"]["reason"].startswith(
            "failed to parse setting [scroll] with value [abc]")


class TestAPathThatEndsInASlash:
    """Two products serve it, one redirects, and mockdr refused all three.

    A client that builds its URL by joining a base and a path lands on one
    constantly.  Measured: Elasticsearch serves `/{index}/_search/` and every
    other shape tried, splunkd serves `/services/...` and `/servicesNS/...`
    alike, and Kibana answers `302` pointing at the path with its slashes
    percent-encoded — `/api/cases/_find/` becomes `/api%2Fcases%2F_find`,
    which then answers 404 when followed.  mockdr answered 404 to all of
    them.
    """

    def test_elasticsearch_serves_it(self, client: TestClient) -> None:
        for path in ("/elastic/logs-endpoint/_search/", "/elastic/_cat/indices/",
                     "/elastic/logs-endpoint/_mapping/", "/elastic/_alias/"):
            assert client.get(path, headers=AUTH).status_code == 200, path

    def test_the_mount_root_keeps_its_slash(self, client: TestClient) -> None:
        """`/elastic/` is the cluster's `/`, not a path with one too many."""
        assert client.get("/elastic/", headers=AUTH).status_code == 200

    def test_splunkd_serves_it(self, client: TestClient) -> None:
        splunk = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}
        for path in ("/splunk/services/data/indexes/",
                     "/splunk/services/search/jobs/"):
            resp = client.get(path, headers=splunk, params={"output_mode": "json"})
            assert resp.status_code == 200, path

    def test_kibana_redirects_with_its_slashes_encoded(
        self, client: TestClient,
    ) -> None:
        kibana = {**AUTH, "kbn-xsrf": "true"}
        for path, target in (("/kibana/api/cases/_find/", "/api%2Fcases%2F_find"),
                             ("/kibana/api/status/", "/api%2Fstatus"),
                             ("/kibana/api/fleet/agents/setup/",
                              "/api%2Ffleet%2Fagents%2Fsetup")):
            resp = client.get(path, headers=kibana, follow_redirects=False)
            assert resp.status_code == 302, path
            assert resp.headers["location"] == target, path


class TestEveryIndexAndItsAliases:
    """`GET /_alias` is a route the cluster has and mockdr did not.

    Read as an index name, `_alias` answered `invalid_index_name_exception`.
    Found by asking what a trailing slash does: `/_alias/` strips to
    `/_alias`, and that turned out to be nobody's route.
    """

    def test_it_lists_every_index_and_its_aliases(self, client: TestClient) -> None:
        client.put("/elastic/zzz-alias-probe", headers=AUTH)
        client.put("/elastic/zzz-alias-probe/_alias/zzz-the-alias", headers=AUTH)
        resp = client.get("/elastic/_alias", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["zzz-alias-probe"] == {"aliases": {"zzz-the-alias": {}}}
