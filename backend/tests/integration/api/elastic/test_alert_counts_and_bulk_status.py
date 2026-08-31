"""What a query matched, and what a bulk change actually changed.

Two defects on the same signals surface, both answering 200:

* `hits.total.value` was the size of the index, not the number of matches.
  Every status filter reported 45 — the total number of alerts — so a
  triage view counting with `size: 0`, which is how a triage view counts,
  saw the same number whatever it asked. Measured on Elasticsearch 8.15
  against a four-document index: a `term` query reports 3 and 1, never 4.

* `POST /api/detection_engine/signals/status` accepts two body shapes, and
  its own validation checks both — but the handler only ever read
  `signal_ids`. A change selected by query, the way Kibana's UI selects it,
  answered `updated: 0` for a query matching 28 alerts and changed nothing.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ=",
    "kbn-xsrf": "true",
}
SEARCH = "/kibana/api/detection_engine/signals/search"
STATUS = "/kibana/api/detection_engine/signals/status"
_STATES = ("open", "closed", "acknowledged", "in-progress")


def _by_status(status: str) -> dict:
    return {"bool": {"filter": [{"term": {"signal.status": status}}]}}


def _total(client: TestClient, query: dict) -> int:
    resp = client.post(SEARCH, headers=ES_AUTH, json={"query": query, "size": 0})
    assert resp.status_code == 200, resp.text
    return int(resp.json()["hits"]["total"]["value"])


class TestTheTotalCountsMatches:
    def test_the_states_partition_the_index(self, client: TestClient) -> None:
        everything = _total(client, {"match_all": {}})
        counted = sum(_total(client, _by_status(s)) for s in _STATES)
        assert counted == everything
        assert everything > 1

    def test_a_filter_that_matches_nothing_counts_nothing(
        self, client: TestClient,
    ) -> None:
        assert _total(client, _by_status("no-such-status")) == 0

    def test_the_total_is_not_simply_the_index_size(
        self, client: TestClient,
    ) -> None:
        """The defect itself: every filter answered the same number."""
        everything = _total(client, {"match_all": {}})
        assert _total(client, _by_status("open")) != everything


class TestABulkStatusChangeChanges:
    def test_selecting_by_query_moves_every_match(
        self, client: TestClient,
    ) -> None:
        before = _total(client, _by_status("open"))
        assert before > 10, "fewer than one page of open alerts; nothing to prove"

        resp = client.post(STATUS, headers=ES_AUTH, json={
            "query": _by_status("open"), "status": "closed"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["updated"] == before
        assert body["total"] == before
        assert _total(client, _by_status("open")) == 0

    def test_selecting_by_id_still_works(self, client: TestClient) -> None:
        hits = client.post(SEARCH, headers=ES_AUTH, json={
            "query": _by_status("open"), "size": 2}).json()["hits"]["hits"]
        ids = [h["_id"] for h in hits]
        assert len(ids) == 2

        resp = client.post(STATUS, headers=ES_AUTH, json={
            "signal_ids": ids, "status": "acknowledged"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["updated"] == 2

    def test_a_query_matching_nothing_updates_nothing(
        self, client: TestClient,
    ) -> None:
        resp = client.post(STATUS, headers=ES_AUTH, json={
            "query": _by_status("no-such-status"), "status": "closed"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["updated"] == 0
