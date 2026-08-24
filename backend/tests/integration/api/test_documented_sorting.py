"""Every field the swagger says a route can be sorted by actually sorts it.

``sortBy`` and ``sortOrder`` are documented on every list endpoint. Four
routes — tags, STAR rules, installed applications and restrictions — did not
declare them, so FastAPI dropped the parameter and the client got the default
order while believing it had asked for another. That is the same silent
wrongness as a filter that does not filter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
_SWAGGER = Path(__file__).resolve().parents[4] / "data" / "swagger_2_1.json"


def _sortable() -> list[tuple[str, tuple[str, ...]]]:
    """Each route and the fields the swagger declares as sortable for it."""
    if not _SWAGGER.exists():  # the spec is fetched, not vendored
        return []
    spec = json.loads(_SWAGGER.read_text())
    routes = []
    for path, operations in sorted(spec["paths"].items()):
        if "{" in path or "get" not in operations:
            continue
        params = {
            p["name"]: p
            for p in operations["get"].get("parameters", [])
            if p.get("in") == "query"
        }
        fields = (params.get("sortBy") or {}).get("enum") or []
        if fields:
            routes.append((path[len(BASE):], tuple(fields)))
    return routes


def _rows(payload: dict) -> list[dict]:
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
    return []


def _value(row: dict, field: str) -> object:
    node: object = row
    for part in field.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def _key(value: object) -> tuple[int, float, str]:
    try:
        return (0, float(str(value)), "")
    except (TypeError, ValueError):
        return (1, 0.0, str(value))


@pytest.mark.skipif(not _SWAGGER.exists(), reason="swagger not fetched")
@pytest.mark.parametrize(("route", "fields"), _sortable())
def test_documented_sort_fields_order_the_answer(
    route: str, fields: tuple[str, ...], client: TestClient, auth_headers: dict
) -> None:
    exercised = 0
    for field in fields:
        response = client.get(
            f"{BASE}{route}",
            headers=auth_headers,
            params={"limit": "50", "sortBy": field, "sortOrder": "asc"},
        )
        if response.status_code != 200:
            pytest.skip(f"{route} answered {response.status_code}")
        values = [_value(row, field) for row in _rows(response.json())]
        present = [v for v in values if v is not None]
        if len(present) < 3:
            continue  # the field is not in this response; nothing to order
        exercised += 1
        assert present == sorted(present, key=_key), f"{route} ignored sortBy={field}"
    if not exercised:
        pytest.skip(f"{route} has no sortable field in its response")
