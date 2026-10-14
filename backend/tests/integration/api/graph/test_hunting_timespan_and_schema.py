"""Graph's runHuntingQuery honours `Timespan`, and an empty result reports the projection.

`Timespan` is "The interval of time over which to query data, in ISO 8601
format. The default value is 30 days", in five documented forms --
Date/Date, Duration/endDate, Start/duration, a bare duration and a single
date (https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0).
The route read nothing of it: every hunt saw every seeded row.

And the schema of a hunt that matched nothing fell back to the *source
table's* columns, so `| where false | project DeviceId` described every
column of DeviceInfo -- on both the Graph and the Defender routes.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from application.graph.security.queries import InvalidTimespanError, hunting_window

URL = "/graph/v1.0/security/runHuntingQuery"


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamps(client: TestClient, headers: dict[str, str], body: dict) -> list[datetime]:
    response = client.post(URL, headers=headers, json=body)
    assert response.status_code == 200, response.text
    return [datetime.fromisoformat(r["Timestamp"].replace("Z", "+00:00"))
            for r in response.json()["results"]]


class TestTimespanForms:
    """Each documented form selects the window it describes."""

    NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)

    @pytest.mark.parametrize(("timespan", "start", "end"), [
        (None, NOW - timedelta(days=30), NOW),
        ("P7D", NOW - timedelta(days=7), NOW),
        ("PT12H", NOW - timedelta(hours=12), NOW),
        ("2026-10-01T00:00:00Z/2026-10-05T00:00:00Z",
         datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 5, tzinfo=UTC)),
        ("P2D/2026-10-05T00:00:00Z",
         datetime(2026, 10, 3, tzinfo=UTC), datetime(2026, 10, 5, tzinfo=UTC)),
        ("2026-10-01T00:00:00Z/P1D",
         datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 2, tzinfo=UTC)),
        ("2026-10-10T00:00:00Z", datetime(2026, 10, 10, tzinfo=UTC), NOW),
    ])
    def test_window(self, timespan: str | None, start: datetime, end: datetime) -> None:
        assert hunting_window(timespan, now=self.NOW) == (start, end)

    @pytest.mark.parametrize("timespan", ["yesterday", "P", "P1Y", "x/y"])
    def test_an_undocumented_form_is_refused(self, timespan: str) -> None:
        with pytest.raises(InvalidTimespanError):
            hunting_window(timespan, now=self.NOW)


class TestTimespanNarrowsTheHunt:
    """Rows outside the window are not hunted."""

    def test_a_short_timespan_keeps_only_recent_rows(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        everything = _stamps(client, graph_admin_headers,
                             {"Query": "DeviceNetworkEvents", "Timespan": "P90D"})
        recent = _stamps(client, graph_admin_headers,
                         {"Query": "DeviceNetworkEvents", "Timespan": "P3D"})
        cutoff = datetime.now(UTC) - timedelta(days=3, minutes=1)
        assert 0 < len(recent) < len(everything)
        assert all(stamp >= cutoff for stamp in recent)

    def test_the_default_is_thirty_days(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        stamps = _stamps(client, graph_admin_headers, {"Query": "DeviceNetworkEvents"})
        cutoff = datetime.now(UTC) - timedelta(days=30, minutes=1)
        assert stamps and all(stamp >= cutoff for stamp in stamps)

    def test_a_date_range_in_the_past(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        end = datetime.now(UTC) - timedelta(days=5)
        start = end - timedelta(days=5)
        stamps = _stamps(client, graph_admin_headers, {
            "Query": "DeviceNetworkEvents", "Timespan": f"{_iso(start)}/{_iso(end)}",
        })
        assert stamps and all(start <= s <= end for s in stamps)

    def test_a_bad_timespan_is_400(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.post(URL, headers=graph_admin_headers,
                               json={"Query": "DeviceInfo", "Timespan": "last week"})
        assert response.status_code == 400


class TestEmptyResultSchema:
    """No rows: the schema is still the projection's."""

    def test_graph_schema_follows_the_projection(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.post(URL, headers=graph_admin_headers, json={
            "Query": "DeviceInfo | where DeviceName == 'no-such-device' "
                     "| project DeviceId, DeviceName",
        })
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["results"] == []
        assert [c["name"] for c in body["schema"]] == ["DeviceId", "DeviceName"]

    def test_defender_schema_follows_a_summarize(self, client: TestClient) -> None:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        summarize = "| summarize count() by OSPlatform"
        matched = client.post("/mde/api/advancedqueries/run", headers=headers,
                              json={"Query": f"DeviceInfo {summarize}"}).json()
        response = client.post(
            "/mde/api/advancedqueries/run", headers=headers,
            json={"Query": f"DeviceInfo | where DeviceName == 'no-such-device' {summarize}"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["Results"] == []
        # The same columns the query has when it does match something.
        assert [c["Name"] for c in body["Schema"]] == [c["Name"] for c in matched["Schema"]]
        assert "OSPlatform" in [c["Name"] for c in body["Schema"]]
