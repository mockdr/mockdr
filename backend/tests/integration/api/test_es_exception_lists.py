"""Integration tests for Kibana Exception Lists API.

Verifies exception list and exception item CRUD, find with pagination,
and filtering at ``/kibana/api/exception_lists``.
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}

KBN_WRITE_HEADERS = {
    **ES_AUTH,
    "kbn-xsrf": "true",
}


def _get_first_list(client: TestClient) -> dict:
    """Return the first seeded exception list dict."""
    body = client.get(
        "/kibana/api/exception_lists/_find",
        headers=ES_AUTH,
        params={"per_page": 1},
    ).json()
    return body["data"][0]


def _get_first_item(client: TestClient, list_id: str) -> dict:
    """Return the first seeded exception item for the given list_id."""
    body = client.get(
        "/kibana/api/exception_lists/items/_find",
        headers=ES_AUTH,
        params={"list_id": list_id, "per_page": 1},
    ).json()
    return body["data"][0]


# ── Exception Lists ──────────────────────────────────────────────────────────


class TestFindLists:
    """Tests for GET /kibana/api/exception_lists/_find."""

    def test_find_returns_200(self, client: TestClient) -> None:
        """Find endpoint should return 200."""
        resp = client.get("/kibana/api/exception_lists/_find", headers=ES_AUTH)
        assert resp.status_code == 200

    def test_find_has_kibana_pagination(self, client: TestClient) -> None:
        """Response must include page, per_page, total, and data."""
        body = client.get("/kibana/api/exception_lists/_find", headers=ES_AUTH).json()
        assert "page" in body
        assert "per_page" in body
        assert "total" in body
        assert "data" in body

    def test_find_returns_5_seeded_lists(self, client: TestClient) -> None:
        """Seeder creates 5 exception lists."""
        body = client.get(
            "/kibana/api/exception_lists/_find",
            headers=ES_AUTH,
            params={"per_page": 50},
        ).json()
        assert body["total"] == 5

    def test_list_id_belongs_to_the_items_search_and_is_refused_here(
        self, client: TestClient,
    ) -> None:
        """Measured on 8.15: the list search does not take `list_id`.

        It belongs to `/api/exception_lists/items/_find`, which finds the
        items *of* a list.  mockdr accepted it here and filtered by it, so a
        client narrowing the list search that way got a narrowed answer from
        the mock and a 400 from the product.
        """
        resp = client.get(
            "/kibana/api/exception_lists/_find", headers=ES_AUTH,
            params={"list_id": "zzz"},
        )
        assert resp.status_code == 400
        assert resp.json()["message"] == '[request query]: invalid keys "list_id"'

    def test_the_items_search_still_takes_it(self, client: TestClient) -> None:
        """Where Kibana does know the member, mockdr must keep knowing it."""
        list_id = _get_first_list(client)["list_id"]
        resp = client.get(
            "/kibana/api/exception_lists/items/_find", headers=ES_AUTH,
            params={"list_id": list_id},
        )
        assert resp.status_code == 200

    def test_list_has_required_fields(self, client: TestClient) -> None:
        """Each exception list must include key fields."""
        exc_list = _get_first_list(client)
        required = [
            "id", "list_id", "name", "description", "type",
            "namespace_type", "tags", "created_at", "created_by",
        ]
        for field in required:
            assert field in exc_list, f"Missing list field: {field}"


class TestGetList:
    """Tests for GET /kibana/api/exception_lists?list_id=..."""

    def test_get_list_by_list_id(self, client: TestClient) -> None:
        """Getting a list by its list_id should return the full list."""
        exc_list = _get_first_list(client)
        resp = client.get(
            "/kibana/api/exception_lists",
            headers=ES_AUTH,
            params={"list_id": exc_list["list_id"]},
        )
        assert resp.status_code == 200
        assert resp.json()["list_id"] == exc_list["list_id"]

    def test_get_list_by_internal_id(self, client: TestClient) -> None:
        """Getting a list by its internal id should also work."""
        exc_list = _get_first_list(client)
        resp = client.get(
            "/kibana/api/exception_lists",
            headers=ES_AUTH,
            params={"id": exc_list["id"]},
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == exc_list["id"]

    def test_get_nonexistent_list_returns_404(self, client: TestClient) -> None:
        """Non-existent list_id should return 404."""
        resp = client.get(
            "/kibana/api/exception_lists",
            headers=ES_AUTH,
            params={"list_id": "nonexistent-list-id"},
        )
        assert resp.status_code == 404

    def test_get_list_without_params_returns_400(self, client: TestClient) -> None:
        """Missing both list_id and id should return 400."""
        resp = client.get("/kibana/api/exception_lists", headers=ES_AUTH)
        assert resp.status_code == 400


class TestCreateList:
    """Tests for POST /kibana/api/exception_lists."""

    def test_create_list_returns_200(self, client: TestClient) -> None:
        """Creating an exception list with valid data should return 200."""
        resp = client.post(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            json={
                "name": "Test Exception List",
                "description": "Integration test list.",
                "list_id": "test-exception-list",
                "type": "detection",
                "namespace_type": "single",
                "tags": ["test"],
            },
        )
        assert resp.status_code == 200

    def test_create_list_response_has_id(self, client: TestClient) -> None:
        """Newly created list should have an assigned ID."""
        body = client.post(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            json={
                "name": "ID Check List",
                "type": "detection",
                "description": "created by test",
            },
        ).json()
        assert "id" in body
        assert body["name"] == "ID Check List"

    def test_create_list_without_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header should return 400."""
        resp = client.post(
            "/kibana/api/exception_lists",
            headers=ES_AUTH,
            json={"name": "No XSRF", "type": "detection", "description": "created by test"},
        )
        assert resp.status_code == 400

    def test_created_list_appears_in_find(self, client: TestClient) -> None:
        """A created list should increase the total."""
        before = client.get(
            "/kibana/api/exception_lists/_find",
            headers=ES_AUTH,
            params={"per_page": 200},
        ).json()["total"]

        client.post(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            json={"name": "Findable List", "type": "detection", "description": "created by test"},
        )

        after = client.get(
            "/kibana/api/exception_lists/_find",
            headers=ES_AUTH,
            params={"per_page": 200},
        ).json()["total"]
        assert after == before + 1


class TestUpdateList:
    """Tests for PUT /kibana/api/exception_lists."""

    def test_update_list_name(self, client: TestClient) -> None:
        """Updating a list's name should persist."""
        exc_list = _get_first_list(client)
        resp = client.put(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            json={"id": exc_list["id"], "name": "Renamed Exception List"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Renamed Exception List"

    def test_update_increments_version(self, client: TestClient) -> None:
        """Each update should increment the list version."""
        exc_list = _get_first_list(client)
        original_version = exc_list["version"]
        updated = client.put(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            json={"id": exc_list["id"], "description": "Updated description."},
        ).json()
        assert updated["version"] == original_version + 1

    def test_update_nonexistent_list_returns_404(self, client: TestClient) -> None:
        """Updating a non-existent list should return 404."""
        resp = client.put(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            json={"id": "nonexistent-id", "name": "Ghost", "description": "d",
                  "type": "simple",
                  "entries": [{"field": "a", "operator": "included",
                               "type": "match", "value": "b"}]},
        )
        assert resp.status_code == 404


class TestDeleteList:
    """Tests for DELETE /kibana/api/exception_lists?list_id=..."""

    def test_delete_list_by_list_id(self, client: TestClient) -> None:
        """Deleting a list should remove it and return empty dict."""
        exc_list = _get_first_list(client)
        resp = client.delete(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            params={"list_id": exc_list["list_id"]},
        )
        assert resp.status_code == 200

        # Verify it is gone
        get_resp = client.get(
            "/kibana/api/exception_lists",
            headers=ES_AUTH,
            params={"list_id": exc_list["list_id"]},
        )
        assert get_resp.status_code == 404

    def test_delete_nonexistent_list_returns_404(self, client: TestClient) -> None:
        """Deleting a non-existent list should return 404."""
        resp = client.delete(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
            params={"list_id": "nonexistent-slug"},
        )
        assert resp.status_code == 404

    def test_delete_without_params_returns_400(self, client: TestClient) -> None:
        """Missing both list_id and id should return 400."""
        resp = client.delete(
            "/kibana/api/exception_lists",
            headers=KBN_WRITE_HEADERS,
        )
        assert resp.status_code == 400


# ── Exception Items ──────────────────────────────────────────────────────────


class TestFindItems:
    """Tests for GET /kibana/api/exception_lists/items/_find."""

    def test_find_items_returns_200(self, client: TestClient) -> None:
        """Find items endpoint should return 200."""
        exc_list = _get_first_list(client)
        resp = client.get(
            "/kibana/api/exception_lists/items/_find",
            headers=ES_AUTH,
            params={"list_id": exc_list["list_id"]},
        )
        assert resp.status_code == 200

    def test_find_items_has_kibana_pagination(self, client: TestClient) -> None:
        """Response must include page, per_page, total, and data."""
        exc_list = _get_first_list(client)
        body = client.get(
            "/kibana/api/exception_lists/items/_find",
            headers=ES_AUTH,
            params={"list_id": exc_list["list_id"]},
        ).json()
        assert "page" in body
        assert "per_page" in body
        assert "total" in body
        assert "data" in body

    def test_find_items_filters_by_list_id(self, client: TestClient) -> None:
        """Items returned should all belong to the specified list_id."""
        exc_list = _get_first_list(client)
        body = client.get(
            "/kibana/api/exception_lists/items/_find",
            headers=ES_AUTH,
            params={"list_id": exc_list["list_id"], "per_page": 100},
        ).json()
        for item in body["data"]:
            assert item["list_id"] == exc_list["list_id"]


class TestGetItem:
    """Tests for GET /kibana/api/exception_lists/items?item_id=..."""

    def test_get_item_by_item_id(self, client: TestClient) -> None:
        """Getting an item by its item_id should return the item."""
        exc_list = _get_first_list(client)
        item = _get_first_item(client, exc_list["list_id"])
        resp = client.get(
            "/kibana/api/exception_lists/items",
            headers=ES_AUTH,
            params={"item_id": item["item_id"]},
        )
        assert resp.status_code == 200
        assert resp.json()["item_id"] == item["item_id"]

    def test_get_nonexistent_item_returns_404(self, client: TestClient) -> None:
        """Non-existent item_id should return 404."""
        resp = client.get(
            "/kibana/api/exception_lists/items",
            headers=ES_AUTH,
            params={"item_id": "nonexistent-item-id"},
        )
        assert resp.status_code == 404

    def test_get_item_without_params_returns_400(self, client: TestClient) -> None:
        """Missing both item_id and id should return 400."""
        resp = client.get("/kibana/api/exception_lists/items", headers=ES_AUTH)
        assert resp.status_code == 400

    def test_item_has_required_fields(self, client: TestClient) -> None:
        """Each exception item must include key fields."""
        exc_list = _get_first_list(client)
        item = _get_first_item(client, exc_list["list_id"])
        required = [
            "id", "item_id", "list_id", "name", "description",
            "type", "namespace_type", "entries", "created_at", "created_by",
        ]
        for field in required:
            assert field in item, f"Missing item field: {field}"


class TestCreateItem:
    """Tests for POST /kibana/api/exception_lists/items."""

    def test_create_item_returns_200(self, client: TestClient) -> None:
        """Creating an exception item should return 200."""
        exc_list = _get_first_list(client)
        resp = client.post(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
            json={
                "list_id": exc_list["list_id"],
                "name": "Test Exception Item",
                "description": "Integration test item.",
                "type": "simple",
                "entries": [
                    {"field": "process.name", "operator": "included", "type": "match", "value": "test.exe"},
                ],
            },
        )
        assert resp.status_code == 200

    def test_create_item_response_has_id(self, client: TestClient) -> None:
        """Newly created item should have an assigned ID."""
        exc_list = _get_first_list(client)
        body = client.post(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
            json={
                "list_id": exc_list["list_id"],
                "name": "ID Check Item",
                "description": "Integration test item.",
                "type": "simple",
                "entries": [{"field": "process.name", "operator": "included", "type": "match", "value": "check.exe"}],
            },
        ).json()
        assert "id" in body
        assert body["name"] == "ID Check Item"

    def test_create_item_without_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header should return 400."""
        exc_list = _get_first_list(client)
        resp = client.post(
            "/kibana/api/exception_lists/items",
            headers=ES_AUTH,
            json={
                "list_id": exc_list["list_id"],
                "name": "No XSRF",
                "entries": [],
            },
        )
        assert resp.status_code == 400


class TestUpdateItem:
    """Tests for PUT /kibana/api/exception_lists/items."""

    def test_update_item_name(self, client: TestClient) -> None:
        """Updating an item's name should persist."""
        exc_list = _get_first_list(client)
        item = _get_first_item(client, exc_list["list_id"])
        resp = client.put(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
            # An item update carries the whole item: Kibana's codec requires
            # description, entries, name and type however little is changing.
            json={"id": item["id"], "name": "Renamed Item",
                  "description": item["description"], "type": item["type"],
                  "entries": item["entries"]},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Renamed Item"

    def test_update_nonexistent_item_returns_404(self, client: TestClient) -> None:
        """Updating a non-existent item should return 404."""
        resp = client.put(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
            json={"id": "nonexistent-id", "name": "Ghost", "description": "d",
                  "type": "simple",
                  "entries": [{"field": "a", "operator": "included",
                               "type": "match", "value": "b"}]},
        )
        assert resp.status_code == 404


class TestDeleteItem:
    """Tests for DELETE /kibana/api/exception_lists/items?item_id=..."""

    def test_delete_item_by_item_id(self, client: TestClient) -> None:
        """Deleting an item should remove it from the store."""
        exc_list = _get_first_list(client)
        item = _get_first_item(client, exc_list["list_id"])
        resp = client.delete(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
            params={"item_id": item["item_id"]},
        )
        assert resp.status_code == 200

        # Verify it is gone
        get_resp = client.get(
            "/kibana/api/exception_lists/items",
            headers=ES_AUTH,
            params={"item_id": item["item_id"]},
        )
        assert get_resp.status_code == 404

    def test_delete_nonexistent_item_returns_404(self, client: TestClient) -> None:
        """Deleting a non-existent item should return 404."""
        resp = client.delete(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
            params={"item_id": "nonexistent-item"},
        )
        assert resp.status_code == 404

    def test_delete_item_without_params_returns_400(self, client: TestClient) -> None:
        """Missing both item_id and id should return 400."""
        resp = client.delete(
            "/kibana/api/exception_lists/items",
            headers=KBN_WRITE_HEADERS,
        )
        assert resp.status_code == 400


class TestTheSchemaRunsBeforeTheHandler:
    """An unknown query member is refused even when the required one is there.

    Measured on 8.15 member by member.  `?list_id=<real>&zzzTypo=1` came back
    with the list — a client that had misspelled a second filter read a full
    answer from the mock and got a 400 from the product.  The three routes
    take different sets: the list search takes `list_id`, the item search
    takes `item_id`, and only `summary` also takes `filter`.
    """

    UNKNOWN = "zzzUnknownMember"

    def _list_id(self, client: TestClient) -> str:
        return str(_get_first_list(client)["list_id"])

    def test_a_typo_beside_a_valid_member_is_still_refused(
        self, client: TestClient,
    ) -> None:
        resp = client.get(
            "/kibana/api/exception_lists", headers=ES_AUTH,
            params={"list_id": self._list_id(client), self.UNKNOWN: "1"},
        )
        assert resp.status_code == 400
        assert resp.json()["message"] == (
            f'[request query]: invalid keys "{self.UNKNOWN}"'
        )

    def test_each_route_takes_its_own_id_member(self, client: TestClient) -> None:
        """`list_id` on the list search, `item_id` on the item search."""
        refused = client.get(
            "/kibana/api/exception_lists/items", headers=ES_AUTH,
            params={"list_id": "zzz"},
        )
        assert refused.status_code == 400
        assert refused.json()["message"] == '[request query]: invalid keys "list_id"'

        accepted = client.get(
            "/kibana/api/exception_lists", headers=ES_AUTH,
            params={"list_id": "zzz"},
        )
        assert accepted.status_code == 404, "the member is known; the list is not"

    def test_only_the_summary_takes_filter(self, client: TestClient) -> None:
        summary = client.get(
            "/kibana/api/exception_lists/summary", headers=ES_AUTH,
            params={"list_id": self._list_id(client), "filter": ""},
        )
        assert summary.status_code == 200

        refused = client.get(
            "/kibana/api/exception_lists", headers=ES_AUTH,
            params={"list_id": self._list_id(client), "filter": ""},
        )
        assert refused.status_code == 400
        assert refused.json()["message"] == '[request query]: invalid keys "filter"'
