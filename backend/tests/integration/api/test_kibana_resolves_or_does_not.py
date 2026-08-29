"""Which Kibana routes resolve the object named in the path, and which do not.

Measured on 8.15 by asking every route mockdr serves for a `HEAD` and then
the `GET` behind it — 68 of 72 already agreed, and the four that did not
turned out to be about the GET, not the verb.

* `GET /api/timeline` tells a client what it forgot when *neither* `id` nor
  `template_timeline_id` is there, and answers `{}` as soon as either is —
  an empty `id=` included.  Absent is not empty.
* `/api/cases/{id}/comments` and `/api/cases/{id}/user_actions` never look
  the case up: a case that does not exist is `200 []`.  `GET /api/cases/{id}`
  and `/api/cases/{id}/alerts` beside them *do*, and answer the saved-object
  404.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

ES_AUTH = {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="}
MISSING = "zzz-no-such-case"


class TestTimelineNamesWhatIsMissing:
    def test_neither_parameter_is_a_500_saying_so(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/timeline", headers=ES_AUTH)
        assert resp.status_code == 500
        assert resp.json() == {
            "message": "please provide id or template_timeline_id",
            "status_code": 500,
        }

    def test_an_id_that_names_nothing_is_an_empty_object(
        self, client: TestClient,
    ) -> None:
        resp = client.get("/kibana/api/timeline", headers=ES_AUTH,
                          params={"id": "zzz-none"})
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_an_empty_id_counts_as_given(self, client: TestClient) -> None:
        """`id=` is present, so the route has been told which timeline."""
        resp = client.get("/kibana/api/timeline", headers=ES_AUTH, params={"id": ""})
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_the_template_parameter_counts_too(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/timeline", headers=ES_AUTH,
                          params={"template_timeline_id": "zzz-none"})
        assert resp.status_code == 200
        assert resp.json() == {}


class TestWhichCaseRoutesResolveTheCase:
    def test_the_case_itself_is_a_saved_object_404(self, client: TestClient) -> None:
        resp = client.get(f"/kibana/api/cases/{MISSING}", headers=ES_AUTH)
        assert resp.status_code == 404
        assert resp.json()["message"] == f"Saved object [cases/{MISSING}] not found"

    def test_comments_and_user_actions_do_not_resolve_it(
        self, client: TestClient,
    ) -> None:
        for sub in ("comments", "user_actions"):
            resp = client.get(f"/kibana/api/cases/{MISSING}/{sub}", headers=ES_AUTH)
            assert resp.status_code == 200, sub
            assert resp.json() == [], sub


class TestTheOneMemberACaseTakes:
    """`GET /api/cases/{id}` accepts `includeComments` and nothing else.

    Measured key by key on 8.15 against the 400-versus-not oracle, and the
    effect measured against a throwaway case with one comment on it.
    """

    @staticmethod
    def _a_case(client: TestClient) -> str:
        found = client.get("/kibana/api/cases/_find", headers=ES_AUTH).json()
        return str(found["cases"][0]["id"])

    def test_an_unknown_member_is_refused_before_the_case_is_resolved(
        self, client: TestClient,
    ) -> None:
        """Even for a case that does not exist: the schema runs first."""
        resp = client.get(f"/kibana/api/cases/{MISSING}", headers=ES_AUTH,
                          params={"zzzUnknown": "1"})
        assert resp.status_code == 400
        assert resp.json()["message"] == (
            "[request query.zzzUnknown]: definition for this key is missing"
        )

    def test_include_comments_must_be_one_of_two_literals(
        self, client: TestClient,
    ) -> None:
        case_id = self._a_case(client)
        for value in ("zzz", "1", "0", "yes"):
            resp = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH,
                              params={"includeComments": value})
            assert resp.status_code == 400, value
            assert resp.json()["message"] == (
                "[request query.includeComments]: expected value of type "
                "[boolean] but got [string]"
            ), value

    def test_false_empties_the_list_and_keeps_the_key(
        self, client: TestClient,
    ) -> None:
        case_id = self._a_case(client)
        with_them = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH,
                               params={"includeComments": "true"}).json()
        without = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH,
                             params={"includeComments": "false"}).json()
        assert "comments" in without, "the key stays, the list empties"
        assert without["comments"] == []
        assert len(with_them["comments"]) >= 1

    def test_absent_behaves_as_true(self, client: TestClient) -> None:
        case_id = self._a_case(client)
        bare = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH).json()
        asked = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH,
                           params={"includeComments": "true"}).json()
        assert bare["comments"] == asked["comments"]


class TestTheVersionedRoutesSaySo:
    """`elastic-api-version` belongs to the operation, not the path family.

    8.15 registers some routes through its versioned router and the rest
    plainly, and only the versioned ones answer with `2023-10-31`.  Measured
    operation by operation: `/api/exception_lists/_find` carries one and
    `/api/exception_lists/items/_find` does not; `/api/endpoint/metadata`
    does and `/api/endpoint/action_status` does not.  The header comes from
    dispatch, so a handler's own 500 carries it while a query-schema refusal
    — raised before the handler runs — carries none.
    """

    VERSION = "2023-10-31"

    def test_the_versioned_ones_answer_with_it(self, client: TestClient) -> None:
        for path in ("/kibana/api/data_views",
                     "/kibana/api/detection_engine/rules/_find",
                     "/kibana/api/exception_lists/_find",
                     "/kibana/api/endpoint/metadata",
                     "/kibana/api/timelines"):
            resp = client.get(path, headers=ES_AUTH)
            assert resp.headers.get("elastic-api-version") == self.VERSION, path

    def test_their_neighbours_do_not(self, client: TestClient) -> None:
        for path in ("/kibana/api/exception_lists/items/_find",
                     "/kibana/api/endpoint/action_status",
                     "/kibana/api/cases/_find",
                     "/kibana/api/status",
                     "/kibana/api/alerting/_health"):
            resp = client.get(path, headers=ES_AUTH)
            assert "elastic-api-version" not in {k.lower() for k in resp.headers}, path

    def test_a_handler_error_still_carries_it(self, client: TestClient) -> None:
        """`GET /api/timeline` with no id is a 500 — and a versioned one."""
        resp = client.get("/kibana/api/timeline", headers=ES_AUTH)
        assert resp.status_code == 500
        assert resp.headers.get("elastic-api-version") == self.VERSION

    def test_a_refusal_before_dispatch_does_not(self, client: TestClient) -> None:
        """The header comes from dispatch, and the query schema runs first."""
        resp = client.get("/kibana/api/exception_lists", headers=ES_AUTH,
                          params={"zzzUnknownMember": "1"})
        assert resp.status_code == 400
        assert "elastic-api-version" not in {k.lower() for k in resp.headers}


class TestAContentTypeHapiCannotParse:
    """Kibana's three answers, measured on 8.15 type by type.

    Hapi decides after routing and only for the verbs that carry a payload,
    so a `GET` is never judged.  A header that is not `type/subtype` is a
    400 naming the header; one it has no parser for is a 415; `text/*` and
    the four it does parse reach the route, which answers about the body.
    A header that is *absent* is parsed, not refused — absent is not
    invalid — and the body need not be there at all, which is where this
    differs from Elasticsearch's 406.
    """

    def _post(self, client: TestClient, content_type: str | None, body: str = "{}"):
        headers = dict(ES_AUTH, **{"kbn-xsrf": "true"})
        if content_type is not None:
            headers["Content-Type"] = content_type
        return client.post("/kibana/api/cases", headers=headers, content=body)

    def test_a_media_type_it_cannot_parse_is_415(self, client: TestClient) -> None:
        for content_type in ("application/yaml", "application/xml", "foo/bar",
                             "*/*", "application/*"):
            resp = self._post(client, content_type)
            assert resp.status_code == 415, content_type
            assert resp.json() == {
                "statusCode": 415, "error": "Unsupported Media Type",
                "message": "Unsupported Media Type",
            }, content_type

    def test_a_malformed_header_is_400_naming_the_header(
        self, client: TestClient,
    ) -> None:
        for content_type in ("json", "text/", "/plain"):
            resp = self._post(client, content_type)
            assert resp.status_code == 400, content_type
            assert resp.json()["message"] == "Invalid content-type header", content_type

    def test_what_it_parses_reaches_the_route(self, client: TestClient) -> None:
        """A 400 about the *body*, not about the header."""
        for content_type in ("application/json", "APPLICATION/JSON",
                             "application/json; foo=bar", "text/plain",
                             "text/html", "application/x-www-form-urlencoded",
                             "multipart/form-data", "application/octet-stream"):
            resp = self._post(client, content_type)
            assert resp.status_code == 400, content_type
            assert resp.json()["message"] != "Invalid content-type header", content_type

    def test_an_absent_header_is_not_a_refusal(self, client: TestClient) -> None:
        resp = self._post(client, None)
        assert resp.status_code == 400
        assert resp.json()["message"] != "Invalid content-type header"

    def test_no_body_is_judged_all_the_same(self, client: TestClient) -> None:
        """Unlike Elasticsearch, the header alone decides."""
        resp = self._post(client, "foo/bar", body="")
        assert resp.status_code == 415

    def test_a_get_is_never_judged(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/cases/_find",
                          headers={**ES_AUTH, "Content-Type": "foo/bar"})
        assert resp.status_code == 200
