"""Every date, date-time and duration a Sentinel resource carries parses.

The resources are completed against defaults generated from the ARM spec
(``scripts/gen_arm_fixtures.py``), and the generator wrote ``""`` for every
string -- including the ones the spec types ``format: date-time`` or
``duration``. ``""`` is not a value of either: azure-mgmt-securityinsight's
deserializer raised ``DeserializationError: Invalid datetime string`` on the
first page of ``incidents.list()`` (``systemData.createdAt``) and ``Unable to
parse duration string`` on ``watchlists.list()`` (``defaultDuration``), so
the SDK could read neither collection. ``systemData`` was worse than blank:
the builder completed it over the fixture's blank first, so its own fixed
default found every key present and filled nothing.

An unset date is now null, which every client deserialises as "not set", and
``systemData`` is dated by the resource's own clock where it has one.
"""
from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

WS = (
    "/sentinel/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)

#: The keys these collections carry that the 2024-03-01 spec types as a
#: date-time or a duration.
_DATED = re.compile(
    r"^(createdAt|lastModifiedAt|created|updated|createdTimeUtc|lastModifiedTimeUtc"
    r"|firstActivityTimeUtc|lastActivityTimeUtc|lastModifiedUtc|defaultDuration"
    r"|queryFrequency|queryPeriod|suppressionDuration|eventTime|queryStartTime"
    r"|queryEndTime|timeGenerated|startTimeUtc|endTimeUtc)$",
)


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/sentinel/oauth2/v2.0/token", data={
        "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "grant_type": "client_credentials",
        "scope": "https://management.azure.com/.default",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _dated(value: object, path: str = "") -> Iterator[tuple[str, object]]:
    if isinstance(value, dict):
        for key, item in value.items():
            if _DATED.match(key):
                yield f"{path}.{key}", item
            yield from _dated(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _dated(item, f"{path}[{index}]")


class TestNoBlankDates:
    """No collection answers ``""`` where the spec wants a date or a duration."""

    @pytest.mark.parametrize("collection", [
        "incidents", "alertRules", "watchlists", "bookmarks", "dataConnectors",
    ])
    def test_every_dated_value_is_null_or_a_value(
        self, client: TestClient, collection: str,
    ) -> None:
        response = client.get(f"{WS}/{collection}", headers=_auth(client))
        assert response.status_code == 200, response.text
        assert response.json()["value"], collection
        blank = [path for path, value in _dated(response.json()) if value == ""]
        assert blank == []


class TestSystemData:
    """``systemData`` carries real dates, the resource's own where it has them."""

    def test_an_incidents_system_data_is_its_own_clock(self, client: TestClient) -> None:
        incident = client.get(f"{WS}/incidents", headers=_auth(client)).json()["value"][0]
        system = incident["systemData"]
        assert system["createdAt"] == incident["properties"]["createdTimeUtc"]
        assert system["lastModifiedAt"] == incident["properties"]["lastModifiedTimeUtc"]

    def test_a_resource_without_a_clock_keeps_a_parseable_default(
        self, client: TestClient,
    ) -> None:
        watchlist = client.get(f"{WS}/watchlists", headers=_auth(client)).json()["value"][0]
        assert re.match(r"^\d{4}-\d{2}-\d{2}T", watchlist["systemData"]["createdAt"])
