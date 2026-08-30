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


class TestWhatAControlActionLeavesBehind:
    """Two states a client branches on, measured rather than guessed.

    `pause` puts the job in `PAUSE` — not the `PAUSED` that reads naturally,
    which is exactly why mockdr had it wrong — and `unpause` returns it to
    whatever it had reached.  `finalize` stops the search early and sets
    `isFinalized`, which a job that ran to the end does not have: a client
    reading it is asking whether the results it holds are the whole answer,
    and mockdr answered `false` to both.  Measured on 10.4.2, twice for the
    spelling.
    """

    def test_a_paused_job_says_pause(
        self, client: TestClient, dispatching: None,
    ) -> None:
        sid = _dispatch(client)
        client.post(f"/splunk/services/search/jobs/{sid}/control",
                    headers=AUTH, params=JSON, data={"action": "pause"})
        content = _content(client, sid)
        assert content["dispatchState"] == "PAUSE"
        assert content["isPaused"] is True
        assert content["isDone"] is False

    def test_unpausing_takes_it_back(
        self, client: TestClient, dispatching: None,
    ) -> None:
        sid = _dispatch(client)
        for action in ("pause", "unpause"):
            client.post(f"/splunk/services/search/jobs/{sid}/control",
                        headers=AUTH, params=JSON, data={"action": action})
        content = _content(client, sid)
        assert content["dispatchState"] != "PAUSE"
        assert content["isPaused"] is False

    def test_finalizing_is_visible_and_completing_is_not(
        self, client: TestClient, dispatching: None,
    ) -> None:
        finalized = _dispatch(client)
        client.post(f"/splunk/services/search/jobs/{finalized}/control",
                    headers=AUTH, params=JSON, data={"action": "finalize"})
        content = _content(client, finalized)
        assert content["isFinalized"] is True
        assert content["isDone"] is True

    def test_a_job_that_ran_to_the_end_is_not_finalized(
        self, client: TestClient,
    ) -> None:
        """No dispatch window, so it completes on its own."""
        content = _content(client, _dispatch(client))
        assert content["isDone"] is True
        assert content["isFinalized"] is False
