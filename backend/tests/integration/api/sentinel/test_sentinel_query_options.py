"""Sentinel ``$filter`` and ``$orderby`` on the incidents collection.

``$filter`` was matched with a single regex against the whole expression, so
only the first clause was read and ``and`` / ``or`` were ignored entirely — a
two-clause filter returned everything the first clause matched. Anything the
regex did not recognise returned the full unfiltered list.

``$orderby`` resolved its field with a flat dictionary lookup, so every
``properties/...`` path found nothing and sorted the whole collection equally,
which reads as "sorted" to a caller that cannot see the order it expected.
"""
import pytest
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)
INCIDENTS = f"{SENTINEL_PREFIX}{_WS}/incidents"
API_VERSION = {"api-version": "2024-03-01", "$top": 500}


@pytest.fixture
def arm_headers(client: TestClient) -> dict[str, str]:
    """Bearer headers for the Sentinel (ARM) mount."""
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
        },
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _incidents(client: TestClient, headers: dict, **params: object) -> list:
    resp = client.get(INCIDENTS, headers=headers, params={**API_VERSION, **params})
    assert resp.status_code == 200, resp.text
    return list(resp.json()["value"])


class TestFilter:
    """``$filter`` narrows, including across several clauses."""

    def test_single_clause_narrows(self, client: TestClient, arm_headers: dict) -> None:
        everything = _incidents(client, arm_headers)
        filtered = _incidents(
            client, arm_headers, **{"$filter": "properties/status eq 'New'"},
        )

        assert 0 < len(filtered) < len(everything)
        assert all(i["properties"]["status"] == "New" for i in filtered)

    def test_and_narrows_further_than_either_clause(
        self, client: TestClient, arm_headers: dict,
    ) -> None:
        by_status = _incidents(
            client, arm_headers, **{"$filter": "properties/status eq 'New'"},
        )
        combined = _incidents(client, arm_headers, **{
            "$filter": "properties/status eq 'New' and properties/severity eq 'High'",
        })

        # The second clause used to be discarded, making these identical.
        assert len(combined) < len(by_status)
        assert all(
            i["properties"]["status"] == "New"
            and i["properties"]["severity"] == "High"
            for i in combined
        )

    def test_or_widens(self, client: TestClient, arm_headers: dict) -> None:
        new_only = _incidents(
            client, arm_headers, **{"$filter": "properties/status eq 'New'"},
        )
        either = _incidents(client, arm_headers, **{
            "$filter": "properties/status eq 'New' or properties/status eq 'Active'",
        })

        assert len(either) > len(new_only)

    def test_unmatchable_value_returns_nothing(
        self, client: TestClient, arm_headers: dict,
    ) -> None:
        assert _incidents(
            client, arm_headers, **{"$filter": "properties/status eq 'NoSuchStatus'"},
        ) == []

    def test_bare_field_path_also_works(
        self, client: TestClient, arm_headers: dict,
    ) -> None:
        # Clients write the path both ways.
        with_prefix = _incidents(
            client, arm_headers, **{"$filter": "properties/severity eq 'High'"},
        )
        assert with_prefix


class TestOrderBy:
    """``$orderby`` sorts, including on nested ``properties`` paths."""

    def test_ascending_is_ordered(self, client: TestClient, arm_headers: dict) -> None:
        titles = [
            i["properties"]["title"]
            for i in _incidents(
                client, arm_headers, **{"$orderby": "properties/title asc"},
            )
        ]
        assert titles == sorted(titles)

    def test_descending_reverses(self, client: TestClient, arm_headers: dict) -> None:
        ascending = [
            i["properties"]["title"]
            for i in _incidents(
                client, arm_headers, **{"$orderby": "properties/title asc"},
            )
        ]
        descending = [
            i["properties"]["title"]
            for i in _incidents(
                client, arm_headers, **{"$orderby": "properties/title desc"},
            )
        ]
        assert ascending == list(reversed(descending))

    def test_ordering_changes_the_first_record(
        self, client: TestClient, arm_headers: dict,
    ) -> None:
        default = _incidents(client, arm_headers)
        sorted_by_title = _incidents(
            client, arm_headers, **{"$orderby": "properties/title asc"},
        )
        # A no-op sort left these identical.
        assert default[0]["properties"]["title"] != sorted_by_title[0]["properties"]["title"]

    def test_filter_and_orderby_combine(
        self, client: TestClient, arm_headers: dict,
    ) -> None:
        rows = _incidents(client, arm_headers, **{
            "$filter": "properties/status eq 'New'",
            "$orderby": "properties/title asc",
        })
        titles = [i["properties"]["title"] for i in rows]

        assert titles == sorted(titles)
        assert all(i["properties"]["status"] == "New" for i in rows)
