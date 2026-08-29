"""An index a client made must appear in the listing it asks for.

`_cat/indices` walked a fixed table of built-in prefixes, so a client could
create an index, write documents to it, read them back and find it through
`GET /{index}` — and then not see it in the listing.  Every answer was 200
and every one of them was consistent except the one that mattered.  This is
how the conformance harness came to compare `[]` against a row and report
agreement.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(
    b"elastic:mock-elastic-password").decode()}


class TestCatIndicesListsCreatedIndices:
    def test_an_index_a_client_made_is_listed(self, client: TestClient) -> None:
        name = "zzz-cat-listing"
        assert client.put(f"/elastic/{name}", headers=AUTH).status_code == 200
        client.put(f"/elastic/{name}/_doc/1", headers=AUTH,
                   params={"refresh": "true"}, json={"a": 1})

        listed = client.get("/elastic/_cat/indices", headers=AUTH,
                            params={"format": "json", "h": "index,docs.count"})
        assert listed.status_code == 200
        rows = {r["index"]: r for r in listed.json()}
        assert name in rows, f"created index missing from the listing: {sorted(rows)}"
        assert rows[name]["docs.count"] == "1"

    def test_the_scoped_form_finds_it_too(self, client: TestClient) -> None:
        name = "zzz-cat-listing-scoped"
        client.put(f"/elastic/{name}", headers=AUTH)
        scoped = client.get(f"/elastic/_cat/indices/{name}", headers=AUTH,
                            params={"format": "json", "h": "index"})
        assert scoped.status_code == 200
        assert [r["index"] for r in scoped.json()] == [name]

    def test_a_deleted_index_leaves_the_listing(self, client: TestClient) -> None:
        name = "zzz-cat-listing-gone"
        client.put(f"/elastic/{name}", headers=AUTH)
        assert client.delete(f"/elastic/{name}", headers=AUTH).status_code == 200
        listed = client.get("/elastic/_cat/indices", headers=AUTH,
                            params={"format": "json", "h": "index"})
        assert name not in {r["index"] for r in listed.json()}

    def test_the_built_in_indices_are_still_there(self, client: TestClient) -> None:
        """Adding the created ones must not displace the seeded ones."""
        listed = client.get("/elastic/_cat/indices", headers=AUTH,
                            params={"format": "json", "h": "index"})
        names = {r["index"] for r in listed.json()}
        assert {".siem-signals", ".alerts-security"} <= names
