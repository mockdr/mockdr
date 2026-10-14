"""`results_preview`, which splunklib's `Job.preview()` reads, and maxresultrows."""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
JOBS = "/splunk/services/search/jobs"
JOBS_V2 = "/splunk/services/search/v2/jobs"


def _job(client: TestClient, search: str = "search index=sentinelone") -> str:
    return str(client.post(JOBS, data={"search": search}, headers=AUTH,
                           params={"output_mode": "json"}).json()["sid"])


class TestResultsPreview:
    """There was no `results_preview` route.

    splunklib's `Job.preview()` GETs `search/jobs/{sid}/results_preview` on
    v1 and POSTs `search/v2/jobs/{sid}/results_preview` on v2
    (splunklib/client.py); v1 answered "Unknown sid." for a job that existed
    and v2 "Unknown endpoint.". The REST reference: "When the job is complete,
    this gives the same response as /search/jobs/{search_id}/results."
    """

    def test_a_finished_job_previews_its_results(self, client: TestClient) -> None:
        sid = _job(client)
        params = {"output_mode": "json", "count": 5}
        results = client.get(f"{JOBS}/{sid}/results", headers=AUTH, params=params)
        for method, base in (("GET", JOBS), ("POST", JOBS_V2), ("GET", JOBS_V2)):
            preview = client.request(method, f"{base}/{sid}/results_preview",
                                     headers=AUTH, params=params)
            assert preview.status_code == 200, (method, base, preview.text)
            assert preview.json() == results.json()
            assert preview.json()["preview"] is False

    def test_an_unknown_sid(self, client: TestClient) -> None:
        for base in (JOBS, JOBS_V2):
            resp = client.get(f"{base}/0000000000.000000/results_preview",
                              headers=AUTH, params={"output_mode": "json"})
            assert resp.status_code == 404
            assert resp.json()["messages"] == [{"type": "FATAL", "text": "Unknown sid."}]

    def test_a_running_job_says_it_is_a_preview(
        self, client: TestClient, monkeypatch: object,
    ) -> None:
        from application.splunk.queries import search as search_queries

        monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 30.0)  # type: ignore[attr-defined]
        sid = _job(client)
        body = client.post(f"{JOBS_V2}/{sid}/results_preview", headers=AUTH,
                           params={"output_mode": "json"}).json()
        assert body["preview"] is True


class TestCountIsHeldToMaxresultrows:
    """`count` was capped at 10,000 with no reason given.

    `[restapi] maxresultrows` — "Maximum result rows to be returned by
    /events or /results getters from REST API. Default: 50000" (limits.conf
    spec, help.splunk.com).
    """

    def test_the_cap(self) -> None:
        from api.routers.splunk.splunk_search import _capped

        assert _capped(20_000) == 20_000
        assert _capped(60_000) == 50_000
        assert _capped(0) == 50_000

    def test_more_than_ten_thousand_rows_come_back(self, client: TestClient) -> None:
        sid = _job(client, "| makeresults count=12000")
        rows = client.get(f"{JOBS}/{sid}/results", headers=AUTH,
                          params={"output_mode": "json", "count": 20_000}).json()["results"]
        assert len(rows) == 12_000
