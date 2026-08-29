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
