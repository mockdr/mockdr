"""The Logs query API applies the body's ``timespan``.

"timespan: The timespan over which to query data. This is an ISO8601 time
period value. This timespan is applied in addition to any that are specified
in the query expression" (Azure Monitor Log Analytics, Query - Execute). The
route read ``query`` and nothing else, so every query saw the workspace's
whole history. azure-monitor-query's ``LogsQueryClient.query_workspace``
takes ``timespan`` as a required argument and sends it on every call -- a
``timedelta`` as ``"PT2592000.0S"``, a ``(start, end)`` tuple as
``"<start>/<end>"`` (``azure/monitor/query/_helpers.py``,
``construct_iso8601``) -- and both were ignored.

The bodies below are the ones that client writes.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

URL = "/sentinel/v1/workspaces/mockdr-workspace/query"


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/sentinel/oauth2/v2.0/token", data={
        "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.loganalytics.io/.default",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _times(client: TestClient, body: dict) -> list[datetime]:
    response = client.post(URL, headers=_auth(client),
                           json={"query": "SecurityIncident | project TimeGenerated", **body})
    assert response.status_code == 200, response.text
    return [datetime.fromisoformat(str(row[0]).replace("Z", "+00:00"))
            for row in response.json()["tables"][0]["rows"]]


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TestTimespanNarrows:
    """Rows outside the requested period are not returned."""

    def test_a_duration_counts_back_from_now(self, client: TestClient) -> None:
        everything = _times(client, {})
        one_day = _times(client, {"timespan": f"PT{timedelta(days=1).total_seconds()}S"})
        cutoff = datetime.now(UTC) - timedelta(days=1, minutes=1)
        assert 0 < len(one_day) < len(everything)
        assert all(stamp >= cutoff for stamp in one_day)

    def test_a_start_and_end_select_that_interval(self, client: TestClient) -> None:
        end = datetime.now(UTC) - timedelta(days=2)
        start = end - timedelta(days=5)
        stamps = _times(client, {"timespan": f"{_iso(start)}/{_iso(end)}"})
        assert stamps
        assert all(start <= stamp <= end for stamp in stamps)

    def test_no_timespan_means_no_window(self, client: TestClient) -> None:
        assert len(_times(client, {})) == len(_times(client, {"timespan": None}))


class TestTimespanRefused:
    """A timespan that is not ISO 8601 is a bad argument, not ignored."""

    def test_an_unreadable_timespan_is_400(self, client: TestClient) -> None:
        response = client.post(URL, headers=_auth(client),
                               json={"query": "SecurityIncident", "timespan": "last week"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "BadArgumentError"

    def test_a_timespan_that_is_not_a_string_is_400(self, client: TestClient) -> None:
        response = client.post(URL, headers=_auth(client),
                               json={"query": "SecurityIncident", "timespan": 30})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "BadArgumentError"
