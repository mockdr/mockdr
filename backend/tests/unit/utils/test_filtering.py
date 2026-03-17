"""Unit tests for utils.filtering — FilterSpec and apply_filters."""

from utils.filtering import FilterSpec, apply_filters

RECORDS = [
    {"id": "a", "name": "alpha", "score": 10, "active": True,  "nested": {"tag": "X"}, "createdAt": "2024-01-01T00:00:00Z"},
    {"id": "b", "name": "beta",  "score": 20, "active": False, "nested": {"tag": "Y"}, "createdAt": "2024-06-01T00:00:00Z"},
    {"id": "c", "name": "gamma", "score": 30, "active": True,  "nested": {"tag": "X"}, "createdAt": "2024-12-01T00:00:00Z"},
]


class TestFilterSpecEq:
    def test_matches_exact_value(self) -> None:
        spec = [FilterSpec("name", "name", "eq")]
        result = apply_filters(RECORDS, {"name": "alpha"}, spec)
        assert len(result) == 1
        assert result[0]["id"] == "a"

    def test_no_match_returns_empty(self) -> None:
        spec = [FilterSpec("name", "name", "eq")]
        result = apply_filters(RECORDS, {"name": "zeta"}, spec)
        assert result == []

    def test_missing_param_returns_all(self) -> None:
        spec = [FilterSpec("name", "name", "eq")]
        result = apply_filters(RECORDS, {}, spec)
        assert len(result) == 3


class TestFilterSpecIn:
    def test_single_value(self) -> None:
        spec = [FilterSpec("ids", "id", "in")]
        result = apply_filters(RECORDS, {"ids": "a"}, spec)
        assert [r["id"] for r in result] == ["a"]

    def test_comma_separated_values(self) -> None:
        spec = [FilterSpec("ids", "id", "in")]
        result = apply_filters(RECORDS, {"ids": "a,c"}, spec)
        assert {r["id"] for r in result} == {"a", "c"}

    def test_no_match(self) -> None:
        spec = [FilterSpec("ids", "id", "in")]
        result = apply_filters(RECORDS, {"ids": "z"}, spec)
        assert result == []


class TestFilterSpecContains:
    def test_partial_match(self) -> None:
        spec = [FilterSpec("name", "name", "contains")]
        result = apply_filters(RECORDS, {"name": "alp"}, spec)
        assert result[0]["id"] == "a"

    def test_case_insensitive(self) -> None:
        spec = [FilterSpec("name", "name", "contains")]
        result = apply_filters(RECORDS, {"name": "BETA"}, spec)
        assert result[0]["id"] == "b"


class TestFilterSpecBool:
    def test_true_filter(self) -> None:
        spec = [FilterSpec("active", "active", "bool")]
        result = apply_filters(RECORDS, {"active": "true"}, spec)
        assert all(r["active"] for r in result)
        assert len(result) == 2

    def test_false_filter(self) -> None:
        spec = [FilterSpec("active", "active", "bool")]
        result = apply_filters(RECORDS, {"active": "false"}, spec)
        assert not any(r["active"] for r in result)
        assert len(result) == 1


class TestFilterSpecDatetime:
    def test_gte_filter(self) -> None:
        spec = [FilterSpec("from", "createdAt", "gte_dt")]
        result = apply_filters(RECORDS, {"from": "2024-06-01"}, spec)
        assert {r["id"] for r in result} == {"b", "c"}

    def test_lte_filter(self) -> None:
        spec = [FilterSpec("to", "createdAt", "lte_dt")]
        result = apply_filters(RECORDS, {"to": "2024-06-01"}, spec)
        assert {r["id"] for r in result} == {"a", "b"}

    def test_invalid_date_returns_all(self) -> None:
        spec = [FilterSpec("from", "createdAt", "gte_dt")]
        result = apply_filters(RECORDS, {"from": "not-a-date"}, spec)
        assert len(result) == 3


class TestFilterSpecFullText:
    def test_matches_first_field(self) -> None:
        spec = [FilterSpec("q", "name|id", "full_text")]
        result = apply_filters(RECORDS, {"q": "alp"}, spec)
        assert result[0]["id"] == "a"

    def test_matches_second_field(self) -> None:
        spec = [FilterSpec("q", "name|id", "full_text")]
        result = apply_filters(RECORDS, {"q": "b"}, spec)
        assert result[0]["id"] == "b"


class TestDotPathFilter:
    def test_nested_field_match(self) -> None:
        spec = [FilterSpec("tag", "nested.tag", "in")]
        result = apply_filters(RECORDS, {"tag": "X"}, spec)
        assert {r["id"] for r in result} == {"a", "c"}

    def test_nested_field_no_match(self) -> None:
        spec = [FilterSpec("tag", "nested.tag", "in")]
        result = apply_filters(RECORDS, {"tag": "Z"}, spec)
        assert result == []


class TestMultipleSpecs:
    def test_chained_filters_narrow_results(self) -> None:
        spec = [
            FilterSpec("active", "active", "bool"),
            FilterSpec("tag", "nested.tag", "in"),
        ]
        result = apply_filters(RECORDS, {"active": "true", "tag": "X"}, spec)
        assert {r["id"] for r in result} == {"a", "c"}


# ── Edge cases — _get_field ───────────────────────────────────────────────────


class TestGetFieldEdgeCases:
    """Tests for _get_field dot-path traversal with unusual inputs."""

    def test_missing_intermediate_dict(self) -> None:
        """A dot-path through a missing intermediate key returns None → no crash."""
        records = [{"id": "x", "top": "val"}]
        spec = [FilterSpec("f", "top.sub.deep", "eq")]
        result = apply_filters(records, {"f": "anything"}, spec)
        assert result == []

    def test_field_on_non_dict_value(self) -> None:
        """Traversing a dot-path where an intermediate is a string returns None."""
        records = [{"id": "x", "name": "hello"}]
        spec = [FilterSpec("f", "name.sub", "eq")]
        result = apply_filters(records, {"f": "anything"}, spec)
        assert result == []

    def test_missing_top_level_field(self) -> None:
        """Filtering on a field that doesn't exist in the record at all."""
        records = [{"id": "x"}]
        spec = [FilterSpec("f", "nonexistent", "eq")]
        result = apply_filters(records, {"f": "val"}, spec)
        assert result == []

    def test_none_field_value_coerced_to_empty(self) -> None:
        """A field with value None is coerced via ``str(None or "")`` to ``""``."""
        records = [{"id": "x", "val": None}]
        spec = [FilterSpec("f", "val", "eq")]
        # _get_field returns None → str(None or "") → "" → matches param ""
        # But param "" is skipped by apply_filters, so use a non-empty param:
        result = apply_filters(records, {"f": "something"}, spec)
        assert result == []  # "" != "something"


# ── Edge cases — empty / blank parameters ────────────────────────────────────


class TestEmptyParamEdgeCases:
    """Tests for blank or empty parameter values."""

    def test_empty_string_param_skipped(self) -> None:
        """An empty-string parameter value should be treated as absent."""
        spec = [FilterSpec("name", "name", "eq")]
        result = apply_filters(RECORDS, {"name": ""}, spec)
        assert len(result) == 3  # all records returned

    def test_none_param_skipped(self) -> None:
        """A None parameter value should be treated as absent."""
        spec = [FilterSpec("name", "name", "eq")]
        result = apply_filters(RECORDS, {"name": None}, spec)
        assert len(result) == 3


# ── Edge cases — "in" filter whitespace ──────────────────────────────────────


class TestInFilterWhitespace:
    """Tests for "in" filter handling of whitespace around commas."""

    def test_spaces_around_commas_trimmed(self) -> None:
        spec = [FilterSpec("ids", "id", "in")]
        result = apply_filters(RECORDS, {"ids": " a , c "}, spec)
        assert {r["id"] for r in result} == {"a", "c"}

    def test_trailing_comma_ignored(self) -> None:
        spec = [FilterSpec("ids", "id", "in")]
        result = apply_filters(RECORDS, {"ids": "a,b,"}, spec)
        assert {r["id"] for r in result} == {"a", "b"}


# ── Edge cases — "bool" filter variants ──────────────────────────────────────


class TestBoolFilterVariants:
    """Tests for all accepted truthy values in bool filter."""

    def test_bool_yes(self) -> None:
        spec = [FilterSpec("active", "active", "bool")]
        result = apply_filters(RECORDS, {"active": "yes"}, spec)
        assert len(result) == 2

    def test_bool_1(self) -> None:
        spec = [FilterSpec("active", "active", "bool")]
        result = apply_filters(RECORDS, {"active": "1"}, spec)
        assert len(result) == 2

    def test_bool_TRUE_uppercase(self) -> None:
        spec = [FilterSpec("active", "active", "bool")]
        result = apply_filters(RECORDS, {"active": "TRUE"}, spec)
        assert len(result) == 2

    def test_bool_0_means_false(self) -> None:
        spec = [FilterSpec("active", "active", "bool")]
        result = apply_filters(RECORDS, {"active": "0"}, spec)
        assert len(result) == 1
        assert result[0]["active"] is False


# ── Edge cases — datetime filters ────────────────────────────────────────────


class TestDatetimeEdgeCases:
    """Additional datetime filter edge cases."""

    def test_gte_with_microsecond_format(self) -> None:
        """S1 API uses .000Z format — ensure it parses correctly."""
        records = [
            {"id": "x", "ts": "2024-06-15T12:30:45.123456Z"},
            {"id": "y", "ts": "2024-01-01T00:00:00.000000Z"},
        ]
        spec = [FilterSpec("from", "ts", "gte_dt")]
        result = apply_filters(records, {"from": "2024-06-01"}, spec)
        assert [r["id"] for r in result] == ["x"]

    def test_lte_with_missing_field_excluded(self) -> None:
        """Records missing the datetime field should be excluded, not crash."""
        records = [
            {"id": "x", "ts": "2024-06-01T00:00:00Z"},
            {"id": "y"},  # no "ts" field
        ]
        spec = [FilterSpec("to", "ts", "lte_dt")]
        result = apply_filters(records, {"to": "2024-12-31"}, spec)
        assert [r["id"] for r in result] == ["x"]

    def test_gte_with_unparseable_field_value_excluded(self) -> None:
        """Records whose datetime field can't be parsed should be excluded."""
        records = [
            {"id": "x", "ts": "not-a-date"},
            {"id": "y", "ts": "2024-06-01T00:00:00Z"},
        ]
        spec = [FilterSpec("from", "ts", "gte_dt")]
        result = apply_filters(records, {"from": "2024-01-01"}, spec)
        assert [r["id"] for r in result] == ["y"]

    def test_gte_and_lte_combined_range(self) -> None:
        """Combining gte_dt and lte_dt produces a date range."""
        spec = [
            FilterSpec("from", "createdAt", "gte_dt"),
            FilterSpec("to", "createdAt", "lte_dt"),
        ]
        result = apply_filters(RECORDS, {"from": "2024-03-01", "to": "2024-09-01"}, spec)
        assert [r["id"] for r in result] == ["b"]


# ── Edge cases — full_text filter ────────────────────────────────────────────


class TestFullTextEdgeCases:
    """Additional full_text filter edge cases."""

    def test_full_text_case_insensitive(self) -> None:
        spec = [FilterSpec("q", "name|id", "full_text")]
        result = apply_filters(RECORDS, {"q": "GAMMA"}, spec)
        assert result[0]["id"] == "c"

    def test_full_text_no_match(self) -> None:
        spec = [FilterSpec("q", "name|id", "full_text")]
        result = apply_filters(RECORDS, {"q": "zzzzzzz"}, spec)
        assert result == []

    def test_full_text_matches_on_none_field_gracefully(self) -> None:
        """Full text on a record where one of the pipe fields is None."""
        records = [{"id": "x", "name": None, "desc": "hello"}]
        spec = [FilterSpec("q", "name|desc", "full_text")]
        result = apply_filters(records, {"q": "hello"}, spec)
        assert len(result) == 1
