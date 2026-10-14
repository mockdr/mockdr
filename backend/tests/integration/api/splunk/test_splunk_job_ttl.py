"""A search job lives for its ttl, as splunkd's reaper allows, and no longer.

limits.conf ``[search] ttl = 600``: "How long, in seconds, the search
artifacts should be stored on disk after the job completes", counted from
the job's last modification, which an active viewer keeps fresh so "the
reaper does not remove the job from underneath" (Splunk 10.4
limits.conf.spec). The mock kept every job until a cap of 5,000 evicted
the oldest — each holding its whole result set and matched events — so a
client that dispatched a search per poll grew the process for hours, and a
job read a day later still answered.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from repository.splunk.search_job_repo import search_job_repo
from tests.clock import Clock

_AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


def _dispatch(client: TestClient) -> str:
    response = client.post("/splunk/services/search/jobs", headers=_AUTH,
                           data={"search": "search index=main | head 3"})
    assert response.status_code == 201, response.text
    return str(response.json()["sid"])


def test_a_job_left_alone_past_its_ttl_is_gone(client: TestClient, clock: Clock) -> None:
    sid = _dispatch(client)
    clock.advance(601)

    assert client.get(f"/splunk/services/search/jobs/{sid}", headers=_AUTH).status_code == 404
    listed = client.get("/splunk/services/search/jobs", headers=_AUTH).json()["entry"]
    assert sid not in {entry["name"] for entry in listed}


def test_a_job_inside_its_ttl_still_answers(client: TestClient, clock: Clock) -> None:
    sid = _dispatch(client)
    clock.advance(599)

    assert client.get(f"/splunk/services/search/jobs/{sid}", headers=_AUTH).status_code == 200


def test_reading_a_job_keeps_it(client: TestClient, clock: Clock) -> None:
    """A client paging a job for longer than ten minutes is viewing it."""
    sid = _dispatch(client)
    for _ in range(4):
        clock.advance(400)
        response = client.get(f"/splunk/services/search/jobs/{sid}/results", headers=_AUTH)
        assert response.status_code == 200, response.text


def test_a_saved_job_lives_a_week(client: TestClient, clock: Clock) -> None:
    sid = _dispatch(client)
    client.post(f"/splunk/services/search/jobs/{sid}/control", headers=_AUTH,
                data={"action": "save"})
    clock.advance(days=6)
    assert client.get(f"/splunk/services/search/jobs/{sid}", headers=_AUTH).status_code == 200
    clock.advance(days=7, seconds=1)
    assert client.get(f"/splunk/services/search/jobs/{sid}", headers=_AUTH).status_code == 404


def test_the_reaper_frees_jobs_nobody_reads(client: TestClient, clock: Clock) -> None:
    for _ in range(3):
        _dispatch(client)
    before = search_job_repo.count()
    clock.advance(601)

    assert search_job_repo.reap() == 3
    assert search_job_repo.count() == before - 3
