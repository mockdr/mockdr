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
