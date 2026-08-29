"""splunkd decides in an order, and the order is visible from outside.

Measured on Splunk 10.4.2 against a job that exists and names that do not.
Three rules the mock had wrong, each of which a client can see:

* the search service words its 405 two ways — the job collections and
  everything addressed *through* a job say `Method Not Allowed`, while
  `jobs/export`, `parser` and `timeparser` say `The method is not allowed.`;
* `/jobs/{sid}` and `/jobs/{sid}/control` resolve the sid before they judge
  the verb, and every read-only sub-resource judges the verb first — so an
  unknown sid is a 404 on the first two and a 405 on the rest;
* an EAI handler maps the verb to an eai action and then looks for the
  trailing segment among that action's custom actions, so
  `DELETE /saved/searches/{name}/dispatch` is a 404 naming all three rather
  than the 400 that says there is no target name.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}  # admin:mockdr-admin
JSON = {"output_mode": "json"}


def _a_job(client: TestClient) -> str:
    resp = client.post("/splunk/services/search/jobs", headers=AUTH, params=JSON,
                       data={"search": "search index=main | head 1"})
    assert resp.status_code in (200, 201), resp.text
    return str(resp.json()["sid"])


class TestTheTwoWordings:
    """Which 405 wording belongs to which path."""

    def test_a_job_and_its_sub_resources_say_method_not_allowed(
        self, client: TestClient,
    ) -> None:
        sid = _a_job(client)
        # Not the job itself: it takes DELETE, and sending one would leave
        # every later sub-resource asking about a job that is gone.
        for sub in ("/control", "/results", "/events", "/summary", "/timeline"):
            resp = client.request(
                "DELETE", f"/splunk/services/search/jobs/{sid}{sub}",
                headers=AUTH, params=JSON,
            )
            assert resp.status_code == 405, (sub, resp.text)
            assert resp.json()["messages"][0] == {
                "type": "FATAL", "text": "Method Not Allowed"}, sub
            assert "allow" in {k.lower() for k in resp.headers}, sub

    def test_export_and_the_parsers_say_the_other_one(
        self, client: TestClient,
    ) -> None:
        for path in ("/splunk/services/search/jobs/export",
                     "/splunk/services/search/v2/jobs/export",
                     "/splunk/services/search/parser",
                     "/splunk/services/search/timeparser"):
            resp = client.request("DELETE", path, headers=AUTH, params=JSON)
            assert resp.status_code == 405, path
            assert resp.json()["messages"][0] == {
                "type": "FATAL", "text": "The method is not allowed."}, path


class TestWhenTheSidIsResolvedFirst:
    """Only the two endpoints that take a write look the job up."""

    def test_the_job_and_its_control_answer_unknown_sid(
        self, client: TestClient,
    ) -> None:
        for path in ("/splunk/services/search/jobs/zzz-no-sid/control",
                     "/splunk/services/search/v2/jobs/zzz-no-sid/control"):
            resp = client.request("DELETE", path, headers=AUTH, params=JSON)
            assert resp.status_code == 404, path
            assert resp.json()["messages"][0] == {
                "type": "FATAL", "text": "Unknown sid."}, path

    def test_a_read_only_sub_resource_judges_the_verb_first(
        self, client: TestClient,
    ) -> None:
        for sub in ("results", "events", "summary", "timeline"):
            resp = client.request(
                "DELETE", f"/splunk/services/search/jobs/zzz-no-sid/{sub}",
                headers=AUTH, params=JSON,
            )
            assert resp.status_code == 405, sub
            assert resp.json()["messages"][0] == {
                "type": "FATAL", "text": "Method Not Allowed"}, sub

    def test_put_and_patch_never_get_that_far(self, client: TestClient) -> None:
        """Refused above the handler, so the sid is never looked at."""
        for verb in ("PUT", "PATCH"):
            resp = client.request(
                verb, "/splunk/services/search/jobs/zzz-no-sid/control",
                headers=AUTH, params=JSON,
            )
            assert resp.status_code == 405, verb
            assert resp.json()["messages"][0] == {
                "type": "ERROR", "text": "Method Not Allowed"}, verb


class TestACustomActionThatIsNotOne:
    """The 400 about a missing target name was nonsense on a named path."""

    def test_saved_search_sub_paths(self, client: TestClient) -> None:
        for action in ("dispatch", "history"):
            resp = client.request(
                "DELETE", f"/splunk/services/saved/searches/zzz-none/{action}",
                headers=AUTH, params=JSON,
            )
            assert resp.status_code == 404, action
            assert resp.json()["messages"][0]["text"] == (
                "Invalid custom action for this internal handler "
                f"(handler: savedsearch, custom action: {action}, "
                "eai action: remove)."
            ), action

    def test_an_index_action(self, client: TestClient) -> None:
        resp = client.request(
            "DELETE", "/splunk/services/data/indexes/main/zzz-act",
            headers=AUTH, params=JSON,
        )
        assert resp.status_code == 404
        assert resp.json()["messages"][0]["text"] == (
            "Invalid custom action for this internal handler "
            "(handler: indexes, custom action: zzz-act, eai action: remove)."
        )


class TestTheLinkBackToTheJob:
    """splunkd points every job-addressed answer back at the job.

    Measured on 10.4.2 against a job that exists and sids that do not: the
    header is there on 200, 204, 404 and 405 alike, and it is relative to the
    request — the job itself gets `<sid>`, a sub-resource `<../sid>`, one
    level deeper `<../../sid>`.  The collection carries none, and neither do
    `jobs/export`, `typeahead` or `parser`, which are not jobs.  A client
    following it reaches the job a partial answer belongs to, which is why a
    204 from `/results` carries one.
    """

    def test_the_job_links_to_itself(self, client: TestClient) -> None:
        sid = _a_job(client)
        resp = client.get(f"/splunk/services/search/jobs/{sid}",
                          headers=AUTH, params=JSON)
        assert resp.headers["link"] == f"<{sid}>; rel=info"

    def test_a_sub_resource_climbs_one_level(self, client: TestClient) -> None:
        sid = _a_job(client)
        for sub in ("results", "events", "summary", "control"):
            resp = client.get(f"/splunk/services/search/jobs/{sid}/{sub}",
                              headers=AUTH, params=JSON)
            assert resp.headers["link"] == f"<../{sid}>; rel=info", sub

    def test_the_v2_paths_carry_it_too(self, client: TestClient) -> None:
        sid = _a_job(client)
        resp = client.get(f"/splunk/services/search/v2/jobs/{sid}/results",
                          headers=AUTH, params=JSON)
        assert resp.headers["link"] == f"<../{sid}>; rel=info"

    def test_a_sid_that_never_existed_is_linked_all_the_same(
        self, client: TestClient,
    ) -> None:
        """The header is the path's, not the job's — 404s carry it."""
        resp = client.get("/splunk/services/search/jobs/zzz-none/search.log",
                          headers=AUTH, params=JSON)
        assert resp.status_code == 404
        assert resp.headers["link"] == "<../zzz-none>; rel=info"

    def test_one_level_deeper_climbs_twice(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/search/jobs/zzz-none/a/b",
                          headers=AUTH, params=JSON)
        assert resp.headers["link"] == "<../../zzz-none>; rel=info"

    def test_what_is_not_a_job_carries_none(self, client: TestClient) -> None:
        for path in ("/splunk/services/search/jobs",
                     "/splunk/services/search/jobs/export",
                     "/splunk/services/search/v2/jobs/export",
                     "/splunk/services/search/typeahead",
                     "/splunk/services/search/parser"):
            resp = client.get(path, headers=AUTH, params=JSON)
            assert "link" not in {k.lower() for k in resp.headers}, path
