"""KV Store data API behaviour.

``query``, ``fields``, ``sort``, ``limit`` and ``skip`` are documented on
``GET storage/collections/data/{collection}`` and are exactly what splunklib's
``KVStoreCollectionData.query()`` sends. None were declared on the route, so
FastAPI dropped them and the whole collection came back regardless. The data
API is also JSON-only in real Splunk — ``output_mode`` does not apply — while
mockdr rendered Atom XML, which breaks the SDK unconditionally.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"
DATA_URL = f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data"
COLLECTION = "query_fixture"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


@pytest.fixture
def populated(client: TestClient) -> str:
    """A collection holding three known records."""
    client.post(
        f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config",
        data={"name": COLLECTION},
        headers=_auth(),
    )
    for row in (
        {"name": "alpha", "n": 3, "tier": "gold"},
        {"name": "beta", "n": 1, "tier": "silver"},
        {"name": "gamma", "n": 2, "tier": "gold"},
    ):
        client.post(f"{DATA_URL}/{COLLECTION}", json=row, headers=_auth())
    return COLLECTION


def _get(client: TestClient, collection: str, **params: object) -> list[dict]:
    resp = client.get(f"{DATA_URL}/{collection}", headers=_auth(), params=params)
    assert resp.status_code == 200
    return list(resp.json())


class TestResponsesAreJson:
    """The data API is JSON-only; XML here breaks splunklib outright."""

    def test_content_type_is_json_without_output_mode(
        self, client: TestClient, populated: str,
    ) -> None:
        resp = client.get(f"{DATA_URL}/{populated}", headers=_auth())
        assert resp.headers["content-type"].startswith("application/json")

    def test_body_is_a_json_array(self, client: TestClient, populated: str) -> None:
        resp = client.get(f"{DATA_URL}/{populated}", headers=_auth())
        assert isinstance(resp.json(), list)
        assert not resp.text.lstrip().startswith("<?xml")


class TestQueryParameter:
    """``query`` filters; the operators Splunk documents are supported."""

    def test_equality(self, client: TestClient, populated: str) -> None:
        rows = _get(client, populated, query=json.dumps({"name": "beta"}))
        assert [r["name"] for r in rows] == ["beta"]

    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ({"n": {"$gt": 1}}, 2),
            ({"n": {"$gte": 2}}, 2),
            ({"n": {"$lt": 3}}, 2),
            ({"n": {"$lte": 1}}, 1),
            ({"n": {"$ne": 1}}, 2),
            ({"tier": {"$in": ["gold"]}}, 2),
            ({"name": {"$regex": "^a"}}, 1),
            ({"$or": [{"n": 1}, {"n": 3}]}, 2),
            ({"$and": [{"tier": "gold"}, {"n": 3}]}, 1),
        ],
    )
    def test_operators(
        self, client: TestClient, populated: str, query: dict, expected: int,
    ) -> None:
        assert len(_get(client, populated, query=json.dumps(query))) == expected

    def test_no_match_returns_empty(self, client: TestClient, populated: str) -> None:
        assert _get(client, populated, query=json.dumps({"name": "nope"})) == []


class TestProjectionSortAndPaging:
    """The remaining documented parameters."""

    def test_fields_include(self, client: TestClient, populated: str) -> None:
        rows = _get(client, populated, fields="name")
        assert all(set(r) == {"_key", "name"} for r in rows)

    def test_fields_exclude(self, client: TestClient, populated: str) -> None:
        rows = _get(client, populated, fields="tier:0")
        assert all("tier" not in r for r in rows)

    def test_sort_ascending(self, client: TestClient, populated: str) -> None:
        assert [r["n"] for r in _get(client, populated, sort="n")] == [1, 2, 3]

    def test_sort_descending(self, client: TestClient, populated: str) -> None:
        assert [r["n"] for r in _get(client, populated, sort="-n")] == [3, 2, 1]

    def test_limit(self, client: TestClient, populated: str) -> None:
        assert len(_get(client, populated, limit=2)) == 2

    def test_skip(self, client: TestClient, populated: str) -> None:
        assert len(_get(client, populated, skip=1)) == 2

    def test_limit_and_skip_combine(self, client: TestClient, populated: str) -> None:
        rows = _get(client, populated, sort="n", skip=1, limit=1)
        assert [r["n"] for r in rows] == [2]


class TestKeyUniqueness:
    """Splunk documents that duplicate keys are not allowed."""

    def test_duplicate_key_is_rejected(self, client: TestClient, populated: str) -> None:
        first = client.post(
            f"{DATA_URL}/{populated}", json={"_key": "fixed", "n": 1}, headers=_auth(),
        )
        assert first.status_code == 201

        second = client.post(
            f"{DATA_URL}/{populated}", json={"_key": "fixed", "n": 2}, headers=_auth(),
        )
        assert second.status_code == 409

    def test_collection_holds_one_record_per_key(
        self, client: TestClient, populated: str,
    ) -> None:
        client.post(
            f"{DATA_URL}/{populated}", json={"_key": "once", "n": 1}, headers=_auth(),
        )
        client.post(
            f"{DATA_URL}/{populated}", json={"_key": "once", "n": 2}, headers=_auth(),
        )

        rows = _get(client, populated)
        assert sum(1 for r in rows if r.get("_key") == "once") == 1


class TestResponseShapes:
    """Status codes and bodies real Splunk returns."""

    def test_insert_returns_201_and_only_the_key(
        self, client: TestClient, populated: str,
    ) -> None:
        resp = client.post(f"{DATA_URL}/{populated}", json={"x": 1}, headers=_auth())
        assert resp.status_code == 201
        assert set(resp.json()) == {"_key"}

    def test_batch_save_returns_keys_not_documents(
        self, client: TestClient, populated: str,
    ) -> None:
        resp = client.post(
            f"{DATA_URL}/{populated}/batch_save",
            json=[{"a": 1}, {"a": 2}],
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert all(set(r) == {"_key"} for r in resp.json())

    def test_missing_collection_is_404_not_empty_list(self, client: TestClient) -> None:
        # `200 []` is indistinguishable from an empty collection.
        resp = client.get(f"{DATA_URL}/no_such_collection", headers=_auth())
        assert resp.status_code == 404
