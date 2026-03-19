"""Unit tests for utils.pagination — cursor-based pagination and response builders."""

import base64
import json

from utils.pagination import AGENT_CURSOR, build_list_response, build_single_response, paginate

ITEMS = [{"id": str(i)} for i in range(25)]


class TestPaginate:
    """Legacy offset-based mode (spec=None)."""

    def test_first_page_no_cursor(self) -> None:
        page, next_cursor, total = paginate(ITEMS, None, 10)
        assert len(page) == 10
        assert page[0]["id"] == "0"
        assert total == 25
        assert next_cursor is not None

    def test_second_page_via_cursor(self) -> None:
        _, cursor, _ = paginate(ITEMS, None, 10)
        page, next_cursor2, total = paginate(ITEMS, cursor, 10)
        assert len(page) == 10
        assert page[0]["id"] == "10"
        assert total == 25

    def test_last_page_has_no_next_cursor(self) -> None:
        _, cursor1, _ = paginate(ITEMS, None, 10)
        _, cursor2, _ = paginate(ITEMS, cursor1, 10)
        page, next_cursor, _ = paginate(ITEMS, cursor2, 10)
        assert len(page) == 5
        assert next_cursor is None

    def test_limit_larger_than_total_returns_all(self) -> None:
        page, next_cursor, total = paginate(ITEMS, None, 100)
        assert len(page) == 25
        assert next_cursor is None
        assert total == 25

    def test_empty_list(self) -> None:
        page, next_cursor, total = paginate([], None, 10)
        assert page == []
        assert next_cursor is None
        assert total == 0

    def test_cursor_is_opaque_string(self) -> None:
        _, cursor, _ = paginate(ITEMS, None, 5)
        assert isinstance(cursor, str)
        assert len(cursor) > 0


class TestPaginateKeyset:
    """S1 keyset-cursor mode (spec provided)."""

    def test_first_page_no_cursor(self) -> None:
        page, cursor, total = paginate(ITEMS, None, 10, AGENT_CURSOR)
        assert len(page) == 10
        assert page[0]["id"] == "0"
        assert total == 25
        assert cursor is not None

    def test_second_page_via_cursor(self) -> None:
        _, cursor, _ = paginate(ITEMS, None, 10, AGENT_CURSOR)
        page, _, total = paginate(ITEMS, cursor, 10, AGENT_CURSOR)
        assert len(page) == 10
        assert page[0]["id"] == "10"
        assert total == 25

    def test_last_page_has_no_next_cursor(self) -> None:
        _, c1, _ = paginate(ITEMS, None, 10, AGENT_CURSOR)
        _, c2, _ = paginate(ITEMS, c1, 10, AGENT_CURSOR)
        page, next_cursor, _ = paginate(ITEMS, c2, 10, AGENT_CURSOR)
        assert len(page) == 5
        assert next_cursor is None

    def test_limit_larger_than_total(self) -> None:
        page, cursor, total = paginate(ITEMS, None, 100, AGENT_CURSOR)
        assert len(page) == 25
        assert cursor is None
        assert total == 25

    def test_empty_list(self) -> None:
        page, cursor, total = paginate([], None, 10, AGENT_CURSOR)
        assert page == []
        assert cursor is None
        assert total == 0

    def test_cursor_has_no_raw_padding(self) -> None:
        # S1 URL-encodes '=' as '%3D' — raw '=' must not appear
        _, cursor, _ = paginate(ITEMS, None, 5, AGENT_CURSOR)
        assert cursor is not None
        assert "=" not in cursor

    def test_cursor_encodes_s1_view_name(self) -> None:
        _, cursor, _ = paginate(ITEMS, None, 5, AGENT_CURSOR)
        assert cursor is not None
        decoded = json.loads(base64.b64decode(cursor.replace("%3D", "=").encode()).decode())
        assert decoded["id_column"] == "AgentView.id"
        assert decoded["id_sort_order"] == "asc"
        assert "id_value" in decoded
        assert "sort_by_column" in decoded
        assert "sort_order" in decoded

    def test_no_overlapping_pages(self) -> None:
        _, c1, _ = paginate(ITEMS, None, 5, AGENT_CURSOR)
        page2, _, _ = paginate(ITEMS, c1, 5, AGENT_CURSOR)
        ids1 = {ITEMS[i]["id"] for i in range(5)}
        ids2 = {r["id"] for r in page2}
        assert ids1.isdisjoint(ids2)


class TestBuildListResponse:
    def test_response_shape(self) -> None:
        page, cursor, total = paginate(ITEMS[:5], None, 5)
        resp = build_list_response(page, cursor, total)
        assert "data" in resp
        assert "pagination" in resp
        assert isinstance(resp["data"], list)
        assert resp["pagination"]["totalItems"] == 5

    def test_next_cursor_in_pagination(self) -> None:
        _, cursor, _ = paginate(ITEMS, None, 10)
        resp = build_list_response(ITEMS[:10], cursor, 25)
        assert resp["pagination"]["nextCursor"] == cursor

    def test_no_next_cursor_when_none(self) -> None:
        resp = build_list_response(ITEMS, None, len(ITEMS))
        assert resp["pagination"]["nextCursor"] is None


class TestBuildSingleResponse:
    def test_wraps_item_in_data(self) -> None:
        item = {"id": "x", "name": "test"}
        resp = build_single_response(item)
        assert resp == {"data": item}

    def test_preserves_all_fields(self) -> None:
        item = {"id": "1", "nested": {"a": 1}}
        resp = build_single_response(item)
        assert resp["data"]["nested"]["a"] == 1
