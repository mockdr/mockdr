"""A job's eventCount, resultCount and scanCount mean what the REST reference says.

search/jobs/{search_id}: eventCount is "the number of events returned by the
search", resultCount "the total number of results returned by the search",
scanCount "the number of events that are scanned or read off disk". The
reference's streaming example answers 287 for all three; its transforming
one (`... | chart sum(kb) by series | sort -sum(kb) | head 5`) answers
eventCount 1363, resultCount 4, scanCount 1363. A `| head 25` job here
reported eventCount 529 -- every event the search terms matched -- and served
all 529 from /events.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
JOBS = "/splunk/services/search/jobs"


def _job(client: TestClient, search: str) -> dict:
    sid = client.post(JOBS, data={"search": search, "output_mode": "json"},
                      headers=AUTH).json()["sid"]
    return client.get(f"{JOBS}/{sid}", params={"output_mode": "json"},
                      headers=AUTH).json()["entry"][0]["content"] | {"sid": sid}


def test_a_streaming_search_returns_as_many_events_as_results(client: TestClient) -> None:
    everything = _job(client, "search index=*")
    assert everything["scanCount"] > 25
    head = _job(client, "search index=* | head 25")
    assert (head["eventCount"], head["resultCount"]) == (25, 25)
    assert head["scanCount"] == everything["scanCount"]
    events = client.get(f"{JOBS}/{head['sid']}/events",
                        params={"output_mode": "json", "count": 0}, headers=AUTH).json()
    assert len(events["results"]) == 25


def test_a_transforming_search_counts_the_events_it_consumed(client: TestClient) -> None:
    everything = _job(client, "search index=*")
    stats = _job(client, "search index=* | stats count by index")
    assert stats["eventCount"] == stats["scanCount"] == everything["scanCount"]
    assert 0 < stats["resultCount"] < stats["eventCount"]
