"""Every Graph collection reads `$top`, or a client asking for a page gets the estate.

Graph pages every collection it serves and this mock read `$top` and `$skip`
on 22 of its collection routes while ignoring them on nine more. Nothing was
wrong on the surface: the answer was a 200 with a `value` array, exactly the
right shape -- just the whole collection, however small a page the client had
asked for. The console asked four of the nine for a page and got everything.

So this asks the rule rather than the nine: if a route answers with a `value`
array, it is a collection, and a collection takes `$top`.
"""
from fastapi.testclient import TestClient

from main import app

#: `/me` and its like answer a single resource, not a collection.
_PREFIX = "/graph/v1.0"


def _collection_routes() -> list[str]:
    """Every parameterless Graph v1.0 GET the mock serves."""
    return sorted(
        path for path, operations in app.openapi()["paths"].items()
        if path.startswith(_PREFIX) and "get" in operations and "{" not in path
    )


def _reads_top(path: str) -> bool:
    """Whether the route declares `$top`."""
    parameters = app.openapi()["paths"][path]["get"].get("parameters", [])
    return any(p["name"] == "$top" for p in parameters)


class TestEveryGraphCollectionPages:
    def test_a_route_answering_with_value_takes_top(
        self, client: TestClient, graph_admin_headers: dict[str, str]
    ) -> None:
        deaf: list[str] = []
        collections = 0

        for path in _collection_routes():
            response = client.get(path, headers=graph_admin_headers)
            if response.status_code != 200:
                continue
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                continue
            collections += 1
            if not _reads_top(path):
                deaf.append(path)

        assert collections >= 25, "the sweep found the Graph mount"
        assert not deaf, f"collections that ignore $top: {deaf}"

    def test_top_returns_a_page_and_says_there_is_more(
        self, client: TestClient, graph_admin_headers: dict[str, str]
    ) -> None:
        for path in _collection_routes():
            if not _reads_top(path):
                continue
            whole = client.get(path, headers=graph_admin_headers)
            if whole.status_code != 200 or not isinstance(whole.json().get("value"), list):
                continue
            total = len(whole.json()["value"])
            if total < 2:
                continue

            page = client.get(path, headers=graph_admin_headers, params={"$top": 1}).json()
            assert len(page["value"]) == 1, path
            assert page.get("@odata.nextLink"), f"{path} has {total} and said nothing follows"

            second = client.get(path, headers=graph_admin_headers,
                                params={"$top": 1, "$skip": 1}).json()
            assert second["value"] != page["value"], f"{path} gave the same row twice"
