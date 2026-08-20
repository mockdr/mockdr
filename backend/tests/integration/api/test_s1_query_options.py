"""SentinelOne list-endpoint query options.

``sortBy``, ``sortOrder`` and ``skip`` are documented on every list endpoint
and were declared on no route, so FastAPI dropped them and a request asking
for a specific order or offset got the default list back — a 200 that looks
like it worked. Several per-endpoint filters had the same shape: a FilterSpec
existed but no parameter did, or a parameter existed with no FilterSpec.
"""
import pytest
from fastapi.testclient import TestClient

PREFIX = "/web/api/v2.1"

# Endpoints with enough seeded rows to observe ordering and offsets.
SORTABLE = [
    ("agents", "computerName"),
    ("threats", "id"),
    ("users", "id"),
    ("exclusions", "id"),
]


def _data(client: TestClient, headers: dict, path: str, **params: object) -> list:
    resp = client.get(f"{PREFIX}{path}", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    body = resp.json()["data"]
    return body if isinstance(body, list) else body.get("sites", [])


@pytest.mark.parametrize(("endpoint", "field"), SORTABLE)
class TestSortBy:
    """``sortBy``/``sortOrder`` order the result set."""

    def test_ascending_and_descending_differ(
        self, client: TestClient, auth_headers: dict, endpoint: str, field: str,
    ) -> None:
        asc = _data(
            client, auth_headers, f"/{endpoint}",
            sortBy=field, sortOrder="asc", limit=100,
        )
        desc = _data(
            client, auth_headers, f"/{endpoint}",
            sortBy=field, sortOrder="desc", limit=100,
        )

        assert [r[field] for r in asc] == list(reversed([r[field] for r in desc]))

    def test_ascending_is_actually_ordered(
        self, client: TestClient, auth_headers: dict, endpoint: str, field: str,
    ) -> None:
        rows = _data(
            client, auth_headers, f"/{endpoint}",
            sortBy=field, sortOrder="asc", limit=100,
        )
        values = [str(r[field]) for r in rows]
        assert values == sorted(values, key=_natural)


def _natural(value: str) -> tuple:
    try:
        return (0, float(value), "")
    except ValueError:
        return (1, 0.0, value)


class TestSkip:
    """``skip`` offsets into the result set."""

    def test_skip_drops_leading_records(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        everything = _data(client, auth_headers, "/agents", limit=100)
        skipped = _data(client, auth_headers, "/agents", skip=10, limit=100)

        assert len(skipped) == len(everything) - 10
        assert skipped[0]["id"] == everything[10]["id"]

    def test_skip_beyond_the_end_returns_nothing(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        assert _data(client, auth_headers, "/agents", skip=9999, limit=100) == []

    def test_skip_zero_is_a_no_op(self, client: TestClient, auth_headers: dict) -> None:
        everything = _data(client, auth_headers, "/agents", limit=100)
        zero = _data(client, auth_headers, "/agents", skip=0, limit=100)
        assert len(zero) == len(everything)


class TestPreviouslyDeadFilters:
    """Filters that were accepted and ignored now select."""

    @pytest.mark.parametrize(
        ("path", "param"),
        [
            ("/cloud-detection/alerts", "categories"),
            ("/exclusions", "value__contains"),
            ("/device-control", "deviceTypes"),
            ("/device-control", "actions"),
            ("/device-control", "deviceClasses"),
        ],
    )
    def test_unmatchable_value_selects_nothing(
        self, client: TestClient, auth_headers: dict, path: str, param: str,
    ) -> None:
        populated = _data(client, auth_headers, path, limit=100)
        assert populated, f"{path} has no seeded rows to filter"

        filtered = _data(
            client, auth_headers, path, limit=100, **{param: "NO_SUCH_VALUE"},
        )
        assert filtered == [], f"{path}?{param}= was ignored"


class TestSitesPagination:
    """``/sites`` never paginated: limit was ignored, nextCursor always None."""

    def test_limit_is_honoured(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            f"{PREFIX}/sites", headers=auth_headers, params={"limit": 1},
        ).json()
        assert len(body["data"]["sites"]) == 1

    def test_next_cursor_is_issued(self, client: TestClient, auth_headers: dict) -> None:
        body = client.get(
            f"{PREFIX}/sites", headers=auth_headers, params={"limit": 1},
        ).json()
        assert body["pagination"]["nextCursor"]

    def test_pages_are_disjoint(self, client: TestClient, auth_headers: dict) -> None:
        first = client.get(
            f"{PREFIX}/sites", headers=auth_headers, params={"limit": 1},
        ).json()
        second = client.get(
            f"{PREFIX}/sites", headers=auth_headers,
            params={"limit": 1, "cursor": first["pagination"]["nextCursor"]},
        ).json()

        assert first["data"]["sites"][0]["id"] != second["data"]["sites"][0]["id"]

    def test_total_counts_the_whole_collection(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        body = client.get(
            f"{PREFIX}/sites", headers=auth_headers, params={"limit": 1},
        ).json()
        assert body["pagination"]["totalItems"] > 1
