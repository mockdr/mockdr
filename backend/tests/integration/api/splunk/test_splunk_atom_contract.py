"""Atom envelope contract for the ``/services`` collection endpoints.

splunklib reads more of the Atom document than mockdr emitted. Every
``Collection.list()`` call does ``parse.unquote(state.links.alternate)``, so an
entry with no ``links`` raised ``AttributeError`` before the caller saw a
single result. And ``splunklib.binding`` rewrites every path to
``/servicesNS/{owner}/{app}/...`` as soon as a client sets a namespace — which
XSOAR's SplunkPy does — so the un-namespaced routes alone 404'd for those
clients.
"""
import base64

import pytest
from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"
COLLECTIONS = [
    "/services/data/indexes",
    "/services/saved/searches",
    "/services/search/jobs",
    "/services/authentication/users",
    "/services/authorization/roles",
    "/services/data/inputs/http",
]


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


def _get(client: TestClient, path: str, **params: object) -> dict:
    resp = client.get(
        f"{SPLUNK_PREFIX}{path}",
        headers=_auth(),
        params={"output_mode": "json", **params},
    )
    assert resp.status_code == 200, path
    return dict(resp.json())


@pytest.mark.parametrize("path", COLLECTIONS)
class TestEntryStructure:
    """What splunklib reads off each entry."""

    def test_entries_carry_links(self, client: TestClient, path: str) -> None:
        for entry in _get(client, path)["entry"]:
            assert "links" in entry, "Collection.list() reads links.alternate"
            assert "alternate" in entry["links"]

    def test_entries_carry_acl(self, client: TestClient, path: str) -> None:
        for entry in _get(client, path)["entry"]:
            assert "acl" in entry, "_parse_atom_metadata hoists acl into Entity.access"

    def test_entry_id_is_absolute(self, client: TestClient, path: str) -> None:
        for entry in _get(client, path)["entry"]:
            assert entry["id"].startswith("https://")

    def test_entry_id_names_its_own_collection(
        self, client: TestClient, path: str,
    ) -> None:
        # Ids used to default to /services/{name}, so a user entry claimed to
        # live at /services/admin rather than under authentication/users.
        for entry in _get(client, path)["entry"]:
            assert path in entry["id"], entry["id"]


@pytest.mark.parametrize("path", COLLECTIONS)
class TestNamespacedPathsAreServed:
    """``/servicesNS/{owner}/{app}/`` reaches the same endpoint."""

    def test_namespaced_form_matches_plain_form(
        self, client: TestClient, path: str,
    ) -> None:
        rest = path[len("/services"):]
        plain = _get(client, path)
        namespaced = _get(client, f"/servicesNS/nobody/search{rest}")

        assert len(namespaced["entry"]) == len(plain["entry"])

    def test_wildcard_namespace_is_served(self, client: TestClient, path: str) -> None:
        rest = path[len("/services"):]
        resp = client.get(
            f"{SPLUNK_PREFIX}/servicesNS/-/-{rest}",
            headers=_auth(),
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200


class TestCollectionPaging:
    """``count`` and ``offset`` are honoured, and ``paging`` describes reality."""

    def test_count_limits_entries(self, client: TestClient) -> None:
        body = _get(client, "/services/data/indexes", count=2)
        assert len(body["entry"]) == 2

    def test_paging_reports_the_page_size_used(self, client: TestClient) -> None:
        # perPage was hardcoded to 30 and contradicted the entries returned.
        body = _get(client, "/services/data/indexes", count=2)
        assert body["paging"]["perPage"] == 2

    def test_offset_skips(self, client: TestClient) -> None:
        everything = _get(client, "/services/data/indexes")["entry"]
        skipped = _get(client, "/services/data/indexes", offset=1)["entry"]

        assert len(skipped) == len(everything) - 1
        assert skipped[0]["name"] == everything[1]["name"]

    def test_count_zero_returns_everything(self, client: TestClient) -> None:
        # Splunk documents 0 as "all entries"; splunklib sets null_count = 0.
        everything = _get(client, "/services/data/indexes")["entry"]
        unlimited = _get(client, "/services/data/indexes", count=0)["entry"]

        assert len(unlimited) == len(everything)

    def test_total_reflects_the_collection_not_the_page(
        self, client: TestClient,
    ) -> None:
        body = _get(client, "/services/data/indexes", count=1)
        assert body["paging"]["total"] > 1


class TestCreateSemantics:
    """Creation answers 201, and a duplicate name is a conflict."""

    def test_index_create_returns_201(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/data/indexes",
            data={"name": "conflict_probe"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        assert resp.status_code == 201

    def test_duplicate_index_is_409(self, client: TestClient) -> None:
        client.post(
            f"{SPLUNK_PREFIX}/services/data/indexes",
            data={"name": "dupe_index"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        second = client.post(
            f"{SPLUNK_PREFIX}/services/data/indexes",
            data={"name": "dupe_index"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        assert second.status_code == 409

    def test_index_delete_is_supported(self, client: TestClient) -> None:
        client.post(
            f"{SPLUNK_PREFIX}/services/data/indexes",
            data={"name": "deletable_index"}, headers=_auth(),
            params={"output_mode": "json"},
        )
        resp = client.delete(
            f"{SPLUNK_PREFIX}/services/data/indexes/deletable_index",
            headers=_auth(), params={"output_mode": "json"},
        )
        # Real Splunk supports DELETE here; the route was absent, so it 405'd.
        assert resp.status_code == 200

    def test_duplicate_saved_search_is_409(self, client: TestClient) -> None:
        payload = {"name": "dupe_search", "search": "search index=main"}
        client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches",
            data=payload, headers=_auth(), params={"output_mode": "json"},
        )
        second = client.post(
            f"{SPLUNK_PREFIX}/services/saved/searches",
            data=payload, headers=_auth(), params={"output_mode": "json"},
        )
        assert second.status_code == 409
