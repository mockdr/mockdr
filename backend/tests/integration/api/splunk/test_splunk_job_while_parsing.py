"""What a job carries before it starts running, which is what a poll reads.

The loop that dispatches a search and polls `isDone` until it is true is the
standard way a SOAR connector talks to Splunk, so the *first* answer that
loop reads is a job that has not finished — and mockdr was answering it with
a finished job's document.

Measured on 10.4.2, state by state: a job carries 36 members while PARSING
and 65 the moment it reaches RUNNING, 69 when done.  The 34 that appear at
that one transition include every counter a client reaches for —
`eventCount`, `resultCount`, `scanCount`, `runDuration` — so a connector
that read them on its first poll got a number from the mock and a missing
key from the product.

QUEUED is treated the same way here: it comes before PARSING and cannot
carry more, though it is too brief to catch on a live instance.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from application.splunk.queries import search as search_queries

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
JSON = {"output_mode": "json"}

#: What splunkd withholds until the search is running.
WITHHELD = (
    "canSummarize", "dropCount", "eventAvailableCount", "eventCount",
    "eventFieldCount", "eventIsStreaming", "eventIsTruncated", "eventSearch",
    "eventSorting", "fieldMetadataEvents", "fieldMetadataResults",
    "fieldMetadataStatic", "indexEarliestTime", "indexLatestTime",
    "isBatchModeSearch", "isRealTimeSearch", "isRemoteTimeline",
    "isTimeCursored", "is_prjob", "keywords", "normalizedSearch",
    "optimizedSearch", "phase0", "phase1", "remoteSearch", "reportSearch",
    "resultCount", "resultIsStreaming", "runDuration", "scanCount",
    "searchCanBeEventType", "searchTelemetry", "searchTotalBucketsCount",
    "searchTotalEliminatedBucketsCount",
)


def _dispatch(client: TestClient) -> str:
    started = client.post("/splunk/services/search/jobs", headers=AUTH, params=JSON,
                          data={"search": "search index=main | head 20"})
    return str(started.json()["sid"])


def _content(client: TestClient, sid: str) -> dict:
    answer = client.get(f"/splunk/services/search/jobs/{sid}", headers=AUTH, params=JSON)
    return dict(answer.json()["entry"][0]["content"])


@pytest.fixture()
def dispatching(monkeypatch: pytest.MonkeyPatch) -> None:
    """A window wide enough that the job is still waiting when it is polled."""
    monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 30.0)


class TestAJobThatHasNotStarted:
    def test_it_carries_none_of_the_counters(
        self, client: TestClient, dispatching: None,
    ) -> None:
        content = _content(client, _dispatch(client))
        assert content["isDone"] is False
        present = [name for name in WITHHELD if name in content]
        assert present == [], present

    def test_it_carries_the_thirty_six_that_are_left(
        self, client: TestClient, dispatching: None,
    ) -> None:
        content = _content(client, _dispatch(client))
        assert len(content) == 36
        # The ones a polling loop steers by are among them.
        for name in ("sid", "dispatchState", "doneProgress", "isDone", "isFailed"):
            assert name in content, name


class TestAFinishedJobCarriesThemAll:
    def test_the_counters_are_back(self, client: TestClient) -> None:
        """With no dispatch window a job is done at once, as it was before."""
        content = _content(client, _dispatch(client))
        assert content["isDone"] is True
        for name in ("eventCount", "resultCount", "scanCount", "runDuration"):
            assert name in content, name
