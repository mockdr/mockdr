"""Advanced Hunting evaluates the KQL it is given.

The query was accepted and never read: every request returned the same three
synthetic rows. A query naming a table that does not exist, or carrying a
``where`` that excludes everything, still came back with results — so a
detection engineer testing a hunting query against mockdr learned nothing
about whether it worked.
"""
import pytest
from fastapi.testclient import TestClient

HUNT_URL = "/mde/api/advancedqueries/run"


@pytest.fixture
def mde_headers(client: TestClient) -> dict[str, str]:
    """Bearer headers for the MDE mount."""
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _hunt(client: TestClient, headers: dict, query: str) -> dict:
    resp = client.post(HUNT_URL, json={"Query": query}, headers=headers)
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


def _rows(client: TestClient, headers: dict, query: str) -> list:
    return list(_hunt(client, headers, query)["Results"])


class TestFiltering:
    """``where`` actually filters."""

    def test_unfiltered_returns_every_device(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        # /api/machines pages at $top=50 by default; hunting sees the table.
        machines = client.get(
            "/mde/api/machines", headers=mde_headers, params={"$top": 1000},
        ).json()["value"]
        assert len(_rows(client, mde_headers, "DeviceInfo")) == len(machines)

    def test_matching_filter_narrows(self, client: TestClient, mde_headers: dict) -> None:
        everything = _rows(client, mde_headers, "DeviceInfo")
        windows = _rows(
            client, mde_headers, 'DeviceInfo | where OSPlatform == "Windows10"',
        )

        assert 0 < len(windows) < len(everything)
        assert all(r["OSPlatform"] == "Windows10" for r in windows)

    def test_non_matching_filter_returns_nothing(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        assert _rows(
            client, mde_headers, 'DeviceInfo | where OSPlatform == "NoSuchOS"',
        ) == []

    @pytest.mark.parametrize(
        "expression",
        [
            'DeviceName contains "desktop"',
            'DeviceName startswith "d"',
            'OSPlatform in ("Windows10", "Linux")',
            'OSPlatform != "Windows10"',
            'OSPlatform == "Windows10" or OSPlatform == "Linux"',
            'not (OSPlatform == "Windows10")',
        ],
    )
    def test_operators_are_understood(
        self, client: TestClient, mde_headers: dict, expression: str,
    ) -> None:
        everything = _rows(client, mde_headers, "DeviceInfo")
        filtered = _rows(client, mde_headers, f"DeviceInfo | where {expression}")

        assert len(filtered) < len(everything), f"{expression} did not filter"

    def test_and_is_narrower_than_either_side(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        left = len(_rows(
            client, mde_headers, 'DeviceInfo | where OSPlatform == "Windows10"',
        ))
        both = len(_rows(
            client, mde_headers,
            'DeviceInfo | where OSPlatform == "Windows10" and HealthStatus == "Active"',
        ))
        assert both <= left


class TestShapingOperators:
    """project, take, distinct, count, order."""

    def test_take_limits(self, client: TestClient, mde_headers: dict) -> None:
        assert len(_rows(client, mde_headers, "DeviceInfo | take 3")) == 3

    def test_project_selects_columns(self, client: TestClient, mde_headers: dict) -> None:
        rows = _rows(client, mde_headers, "DeviceInfo | project DeviceName, OSPlatform")
        assert all(set(r) == {"DeviceName", "OSPlatform"} for r in rows)

    def test_project_away_drops_columns(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        rows = _rows(client, mde_headers, "DeviceInfo | project-away DeviceId")
        assert all("DeviceId" not in r for r in rows)

    def test_distinct_deduplicates(self, client: TestClient, mde_headers: dict) -> None:
        platforms = _rows(client, mde_headers, "DeviceInfo | distinct OSPlatform")
        values = [r["OSPlatform"] for r in platforms]
        assert len(values) == len(set(values))

    def test_count_collapses_to_one_row(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        everything = _rows(client, mde_headers, "DeviceInfo")
        counted = _rows(client, mde_headers, "DeviceInfo | count")

        assert counted == [{"Count": len(everything)}]

    def test_order_by_is_applied(self, client: TestClient, mde_headers: dict) -> None:
        asc = _rows(client, mde_headers, "DeviceInfo | order by DeviceName asc")
        desc = _rows(client, mde_headers, "DeviceInfo | order by DeviceName desc")

        assert [r["DeviceName"] for r in asc] == list(
            reversed([r["DeviceName"] for r in desc]),
        )


class TestSummarize:
    """``summarize`` aggregates."""

    def test_count_by_groups(self, client: TestClient, mde_headers: dict) -> None:
        rows = _rows(client, mde_headers, "DeviceInfo | summarize count() by OSPlatform")
        total = len(_rows(client, mde_headers, "DeviceInfo"))

        assert sum(r["count"] for r in rows) == total

    def test_named_aggregation(self, client: TestClient, mde_headers: dict) -> None:
        rows = _rows(
            client, mde_headers,
            "DeviceInfo | summarize Devices=count() by HealthStatus",
        )
        assert all("Devices" in r for r in rows)

    def test_dcount(self, client: TestClient, mde_headers: dict) -> None:
        rows = _rows(client, mde_headers, "DeviceInfo | summarize dcount(OSPlatform)")
        distinct = _rows(client, mde_headers, "DeviceInfo | distinct OSPlatform")

        assert rows[0]["dcount_OSPlatform"] == len(distinct)


class TestPipelineOrder:
    """Operators run in the order written."""

    def test_filter_then_take(self, client: TestClient, mde_headers: dict) -> None:
        rows = _rows(
            client, mde_headers,
            'DeviceInfo | where OSPlatform == "Windows10" | take 2',
        )
        assert len(rows) == 2
        assert all(r["OSPlatform"] == "Windows10" for r in rows)

    def test_project_then_filter_on_projected_column(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        rows = _rows(
            client, mde_headers,
            'DeviceInfo | project OSPlatform | where OSPlatform == "Linux"',
        )
        assert all(set(r) == {"OSPlatform"} for r in rows)


class TestErrors:
    """A query we cannot run is a 400, not canned rows."""

    def test_unknown_table_is_rejected(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        resp = client.post(
            HUNT_URL, json={"Query": "NoSuchTable"}, headers=mde_headers,
        )
        assert resp.status_code == 400
        assert "table" in resp.json()["error"]["message"].lower()

    def test_unknown_operator_is_rejected(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        resp = client.post(
            HUNT_URL,
            json={"Query": "DeviceInfo | bogusoperator x"},
            headers=mde_headers,
        )
        assert resp.status_code == 400

    def test_empty_query_is_rejected(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        resp = client.post(HUNT_URL, json={"Query": ""}, headers=mde_headers)
        assert resp.status_code == 400


class TestResponseEnvelope:
    """Schema describes the columns actually returned."""

    def test_schema_matches_result_columns(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        body = _hunt(client, mde_headers, "DeviceInfo | project DeviceName | take 1")
        names = [c["Name"] for c in body["Schema"]]

        assert names == ["DeviceName"]

    def test_schema_types_are_reported(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        body = _hunt(client, mde_headers, "DeviceInfo | take 1")
        types = {c["Name"]: c["Type"] for c in body["Schema"]}

        assert types["DeviceName"] == "String"
        assert types["OSBuild"] == "Int64"

    def test_stats_are_present(self, client: TestClient, mde_headers: dict) -> None:
        assert "Stats" in _hunt(client, mde_headers, "DeviceInfo | take 1")


class TestTablesAgreeWithRest:
    """A hunting result must not contradict the REST resources."""

    def test_device_ids_match_the_machines_endpoint(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        rest = {
            m["id"] for m in client.get(
                "/mde/api/machines", headers=mde_headers, params={"$top": 1000},
            ).json()["value"]
        }
        hunted = {r["DeviceId"] for r in _rows(client, mde_headers, "DeviceInfo")}

        assert hunted == rest

    def test_alert_evidence_points_at_real_devices(
        self, client: TestClient, mde_headers: dict,
    ) -> None:
        devices = {r["DeviceId"] for r in _rows(client, mde_headers, "DeviceInfo")}
        evidence = _rows(client, mde_headers, "AlertEvidence")

        assert evidence
        assert all(r["DeviceId"] in devices for r in evidence)
