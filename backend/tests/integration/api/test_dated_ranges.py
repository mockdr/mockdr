"""A dated range filter must select the range the client asked for.

The swagger spells every dated ``__between`` as
``<from_timestamp>-<to_timestamp>`` and gives a 13-digit example
(``1514978764288-1514978999999``) — milliseconds since the epoch. The records
this mock holds carry ISO-8601, so the comparison fell through to text and
``"2026-07-21T08:22:15.000Z" <= "1798761600000"`` is false for every record
ever written: *every* dated range answered 200 with an empty list. A range
spanning the years 2000 to 2100 returned none of the sixty agents it must
contain, and a client reading that concluded the estate was empty.

The numeric ranges the swagger spells the same way — ``coreCount__between=2-8``
— were never affected, and these tests hold them to that.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def _range(low: datetime, high: datetime) -> str:
    return f"{_ms(low)}-{_ms(high)}"


def _agents(client: TestClient, headers: dict, **params: str) -> list[dict]:
    response = client.get(f"{BASE}/agents", headers=headers, params={"limit": "100", **params})
    assert response.status_code == 200, response.text
    return response.json()["data"]


class TestADatedRangeSelectsTheRange:
    def test_a_range_around_every_record_returns_every_record(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        now = datetime.now(UTC)
        everything = _agents(client, auth_headers)
        within = _agents(
            client, auth_headers,
            createdAt__between=_range(now - timedelta(days=3650), now + timedelta(days=3650)),
        )
        assert len(within) == len(everything) > 0

    def test_a_range_before_every_record_returns_none(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        now = datetime.now(UTC)
        before = _agents(
            client, auth_headers,
            createdAt__between=_range(now - timedelta(days=7300), now - timedelta(days=7000)),
        )
        assert before == []

    def test_a_narrow_range_narrows(self, client: TestClient, auth_headers: dict) -> None:
        """Seeded records span about ninety days, so a week is a proper subset."""
        now = datetime.now(UTC)
        everything = _agents(client, auth_headers)
        recent = _agents(
            client, auth_headers,
            createdAt__between=_range(now - timedelta(days=7), now),
        )
        assert 0 <= len(recent) < len(everything)
        for agent in recent:
            created = datetime.strptime(agent["createdAt"], "%Y-%m-%dT%H:%M:%S.%fZ")
            assert created.replace(tzinfo=UTC) >= now - timedelta(days=7)

    def test_a_record_without_the_field_is_not_in_any_range(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """The vendor returns the rows it can compare, not the rows it cannot."""
        now = datetime.now(UTC)
        wide = _range(now - timedelta(days=3650), now + timedelta(days=3650))
        scanned = _agents(client, auth_headers, lastSuccessfulScanDate__between=wide)
        carry = [a for a in _agents(client, auth_headers) if a.get("lastSuccessfulScanDate")]
        assert len(scanned) == len(carry) > 0


class TestTheNumericRangesAreUnchanged:
    def test_a_numeric_range_still_compares_as_numbers(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        agents = _agents(client, auth_headers, coreCount__between="2-8")
        cores = {a["coreCount"] for a in agents}
        assert cores and all(2 <= c <= 8 for c in cores), cores

    def test_a_numeric_range_nothing_reaches_is_empty(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        assert _agents(client, auth_headers, coreCount__between="100-200") == []
