"""Unit tests for CrowdStrike offset/limit pagination."""
from __future__ import annotations

from utils.cs_pagination import paginate_cs


class TestPaginateCs:
    """Tests for ``paginate_cs`` utility."""

    def test_defaults(self) -> None:
        page, total = paginate_cs(list(range(10)))
        assert total == 10
        assert page == list(range(10))

    def test_offset(self) -> None:
        page, total = paginate_cs(list(range(10)), offset=5)
        assert total == 10
        assert page == [5, 6, 7, 8, 9]

    def test_limit(self) -> None:
        page, total = paginate_cs(list(range(10)), limit=3)
        assert total == 10
        assert page == [0, 1, 2]

    def test_offset_and_limit(self) -> None:
        page, total = paginate_cs(list(range(10)), offset=2, limit=3)
        assert page == [2, 3, 4]
        assert total == 10

    def test_offset_beyond_end(self) -> None:
        page, total = paginate_cs(list(range(5)), offset=10)
        assert page == []
        assert total == 5

    def test_empty_list(self) -> None:
        page, total = paginate_cs([])
        assert page == []
        assert total == 0
