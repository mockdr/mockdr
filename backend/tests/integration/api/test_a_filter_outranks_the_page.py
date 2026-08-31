"""A filter decides which records exist; the page size only cuts them up.

`/installed-applications` had the two the wrong way round: it asked the
query layer for one page and then matched `?ids=` against that page. So the
same request answered one row at `limit=1000` and `totalItems: 0` at
`limit=10` — a confident "no such application" for a record sitting on page
two. A client that pages, or that simply uses a smaller default, is told the
thing it just read does not exist.

The sweep asks every S1 collection the same question rather than the one
route that was wrong, because nothing about the mistake was specific to
applications.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _collections(client: TestClient) -> list[tuple[str, str]]:
    """Every S1 collection that declares `ids` and has a second page, with an
    id from the far end of it.

    Only routes that declare the parameter: `/activities` and
    `/restrictions` do not, and what the product does with a query member it
    never declared is a different question, unmeasured here.
    """
    from main import app

    # The declared surface, not `app.routes`: the S1 routers are wrapped and
    # carry no `.path` of their own.
    declared = app.openapi()["paths"]
    found: list[tuple[str, str]] = []
    for path, methods in declared.items():
        if not path.startswith("/web/api/v2.1") or "{" in path or "get" not in methods:
            continue
        names = {p["name"] for p in methods["get"].get("parameters", [])}
        if "ids" not in names or "limit" not in names:
            continue
        resp = client.get(path, headers=AUTH, params={"limit": 1000})
        if resp.status_code != 200:
            continue
        data = resp.json().get("data")
        if not isinstance(data, list) or len(data) < 3:
            continue
        identifier = data[-1].get("id") if isinstance(data[-1], dict) else None
        if identifier is not None:
            found.append((path, str(identifier)))
    return sorted(found)


def test_the_sweep_has_something_to_sweep(client: TestClient) -> None:
    """A sweep over nothing passes for the wrong reason."""
    assert len(_collections(client)) >= 5, (
        "no S1 collection declares both `ids` and `limit` and has a "
        "second page — the sweep would pass over nothing")


def test_ids_answers_the_same_whatever_the_page_size(client: TestClient) -> None:
    disagreed: list[str] = []
    for path, identifier in _collections(client):
        wide = client.get(path, headers=AUTH,
                          params={"ids": identifier, "limit": 1000})
        narrow = client.get(path, headers=AUTH,
                            params={"ids": identifier, "limit": 2})
        if wide.status_code != 200 or narrow.status_code != 200:
            continue
        rows_wide = wide.json().get("data") or []
        rows_narrow = narrow.json().get("data") or []
        if len(rows_wide) != len(rows_narrow):
            disagreed.append(
                f"{path}: limit=1000 -> {len(rows_wide)} rows, "
                f"limit=2 -> {len(rows_narrow)}")
    assert disagreed == []


def test_the_application_that_was_lost_is_found_at_any_page_size(
    client: TestClient,
) -> None:
    """The record the bug was found on, named rather than swept."""
    everything = client.get("/web/api/v2.1/installed-applications",
                            headers=AUTH, params={"limit": 1000})
    apps = everything.json()["data"]
    assert len(apps) > 10, "too few applications to have a second page"
    last = str(apps[-1]["id"])

    for limit in (1000, 10, 1):
        resp = client.get("/web/api/v2.1/installed-applications", headers=AUTH,
                          params={"ids": last, "limit": limit})
        assert resp.status_code == 200, limit
        body = resp.json()
        assert [str(a["id"]) for a in body["data"]] == [last], limit
        assert body["pagination"]["totalItems"] == 1, limit
