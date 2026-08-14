"""Unit tests for the OData ``$filter`` parser shared by MDE and Graph.

Two defects motivated this file, both invisible to the rest of the suite
because nothing exercised them:

* ``contains()``/``startswith()`` raised ``ValueError`` — the tokeniser's
  ``func`` pattern already consumes the opening paren, but the parser asked
  for it a second time, so every call 500'd.
* ``and``/``or`` precedence was flattened into AND-groups-of-ORs, which
  inverts the binding OData specifies.
"""
import pytest

from utils.mde_odata import (
    ODataClause,
    ODataFilterError,
    ODataGroup,
    apply_odata_filter,
    parse_odata_filter,
)

# A single record whose fields spell out the truth table used below.
RECORD = {"a": "F", "b": "F", "c": "T"}


def _matches(filter_str: str, record: dict | None = None) -> bool:
    """Return whether *record* survives *filter_str*."""
    return bool(apply_odata_filter([record if record is not None else RECORD], filter_str))


class TestComparisons:
    """The operators that always worked — guarding against regressions."""

    @pytest.mark.parametrize(("expr", "expected"), [
        ("c eq 'T'", True),
        ("c ne 'T'", False),
        ("a eq 'T'", False),
        ("a ne 'T'", True),
    ])
    def test_equality(self, expr: str, expected: bool) -> None:
        assert _matches(expr) is expected

    @pytest.mark.parametrize(("expr", "expected"), [
        ("n gt 5", True),
        ("n ge 10", True),
        ("n lt 5", False),
        ("n le 10", True),
    ])
    def test_numeric_range(self, expr: str, expected: bool) -> None:
        assert _matches(expr, {"n": 10}) is expected

    def test_lexicographic_fallback_for_timestamps(self) -> None:
        record = {"ts": "2026-08-14T10:00:00Z"}
        assert _matches("ts gt '2026-01-01T00:00:00Z'", record) is True
        assert _matches("ts lt '2026-01-01T00:00:00Z'", record) is False

    def test_missing_field_never_matches(self) -> None:
        assert _matches("nope eq 'T'") is False

    def test_empty_filter_keeps_everything(self) -> None:
        records = [{"x": 1}, {"x": 2}]
        assert apply_odata_filter(records, "") == records
        assert apply_odata_filter(records, "   ") == records


class TestFunctions:
    """``contains()`` and ``startswith()`` — previously a hard 500."""

    @pytest.mark.parametrize(("expr", "expected"), [
        ("contains(x,'ell')", True),
        ("contains(x,'zzz')", False),
        ("startswith(x,'he')", True),
        ("startswith(x,'lo')", False),
    ])
    def test_substring_and_prefix(self, expr: str, expected: bool) -> None:
        assert _matches(expr, {"x": "hello"}) is expected

    def test_case_insensitive(self) -> None:
        assert _matches("contains(x,'ELL')", {"x": "hello"}) is True
        assert _matches("startswith(x,'HE')", {"x": "hello"}) is True

    @pytest.mark.parametrize(("expr", "expected"), [
        ("endswith(mail,'@contoso.com')", True),
        ("endswith(mail,'@other.com')", False),
        ("endswith(mail,'@CONTOSO.COM')", True),
    ])
    def test_endswith(self, expr: str, expected: bool) -> None:
        """Real Graph serves endswith(); omitting it made valid filters 400."""
        assert _matches(expr, {"mail": "a@contoso.com"}) is expected

    def test_nested_slash_path(self) -> None:
        assert _matches("contains(d/h,'ws')", {"d": {"h": "ws-01"}}) is True

    def test_combines_with_boolean_operators(self) -> None:
        record = {"x": "hello"}
        assert _matches("contains(x,'zzz') or startswith(x,'he')", record) is True
        assert _matches("contains(x,'ell') and startswith(x,'he')", record) is True
        assert _matches("contains(x,'ell') and startswith(x,'lo')", record) is False

    def test_parses_to_a_single_clause(self) -> None:
        node = parse_odata_filter("contains(name,'abc')")
        assert node == ODataClause(field="name", operator="contains", value="abc")


class TestPrecedence:
    """``and`` binds tighter than ``or``; parentheses override both."""

    @pytest.mark.parametrize(("expr", "expected"), [
        # (a and b) or c  →  (F and F) or T  →  True
        ("a eq 'T' and b eq 'T' or c eq 'T'", True),
        # c or (a and b)  →  T or (F and F)  →  True
        ("c eq 'T' or a eq 'T' and b eq 'T'", True),
        # plain conjunction / disjunction
        ("a eq 'T' and c eq 'T'", False),
        ("a eq 'T' or c eq 'T'", True),
    ])
    def test_and_binds_tighter_than_or(self, expr: str, expected: bool) -> None:
        assert _matches(expr) is expected

    @pytest.mark.parametrize(("expr", "expected"), [
        ("(a eq 'T' or c eq 'T') and c eq 'T'", True),
        ("(a eq 'T' or b eq 'T') and c eq 'T'", False),
        ("(a eq 'T' or b eq 'T') or c eq 'T'", True),
        ("c eq 'T' and (a eq 'T' or c eq 'T')", True),
    ])
    def test_parentheses_override(self, expr: str, expected: bool) -> None:
        assert _matches(expr) is expected

    def test_tree_shape_reflects_precedence(self) -> None:
        """``x and y or z`` must nest the AND beneath the OR, not the reverse."""
        node = parse_odata_filter("x eq '1' and y eq '2' or z eq '3'")
        assert isinstance(node, ODataGroup)
        assert node.operator == "or"
        assert isinstance(node.children[0], ODataGroup)
        assert node.children[0].operator == "and"
        assert node.children[1] == ODataClause(field="z", operator="eq", value="3")

    def test_single_clause_is_not_wrapped_in_a_group(self) -> None:
        assert parse_odata_filter("x eq '1'") == ODataClause(
            field="x", operator="eq", value="1",
        )


class TestStringLiterals:
    """Quoting rules — OData escapes a literal quote by doubling it."""

    def test_doubled_quote_is_one_literal(self) -> None:
        node = parse_odata_filter("startswith(displayName,'O''Brien')")
        assert node == ODataClause(
            field="displayName", operator="startswith", value="O'Brien",
        )

    def test_doubled_quote_filters_correctly(self) -> None:
        records = [{"displayName": "O'Brien Ltd"}, {"displayName": "Olsen"}]
        got = apply_odata_filter(records, "startswith(displayName,'O''Brien')")
        assert [r["displayName"] for r in got] == ["O'Brien Ltd"]

    def test_empty_string_literal(self) -> None:
        assert _matches("x eq ''", {"x": ""}) is True
        assert _matches("x eq ''", {"x": "y"}) is False


class TestDateTimeLiterals:
    """OData v4 writes date/time literals unquoted."""

    def test_unquoted_timestamp_is_lexed_whole(self) -> None:
        node = parse_odata_filter("createdDateTime ge 2026-08-08T00:00:00Z")
        assert node == ODataClause(
            field="createdDateTime", operator="ge", value="2026-08-08T00:00:00Z",
        )

    def test_day_granularity_is_respected(self) -> None:
        """Lexing only the year made ``ge`` far coarser than requested."""
        records = [{"d": "2026-01-01T00:00:00Z"}, {"d": "2026-08-14T00:00:00Z"}]
        got = apply_odata_filter(records, "d ge 2026-08-08T00:00:00Z")
        assert [r["d"] for r in got] == ["2026-08-14T00:00:00Z"]

    @pytest.mark.parametrize("literal", [
        "2026-08-08",
        "2026-08-08T00:00:00Z",
        "2026-08-08T00:00:00.123Z",
        "2026-08-08T00:00:00+02:00",
    ])
    def test_accepted_shapes(self, literal: str) -> None:
        node = parse_odata_filter(f"d ge {literal}")
        assert isinstance(node, ODataClause)
        assert node.value == literal

    def test_quoted_timestamp_still_works(self) -> None:
        assert _matches("d ge '2026-01-01T00:00:00Z'", {"d": "2026-08-14T00:00:00Z"}) is True


class TestMalformedFilters:
    """Unparseable input must raise, never silently widen the result set."""

    @pytest.mark.parametrize("expr", [
        "os eq 'Windows') and n gt 3",   # stray ')' — tail would be dropped
        "x eq '1' garbage here",         # trailing rubble
        "(x eq '1'",                     # unbalanced '('
        "contains(name,)",               # missing argument
        "x eq",                          # missing value
        "and x eq '1'",                  # leading conjunction
    ])
    def test_malformed_raises(self, expr: str) -> None:
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], expr)

    @pytest.mark.parametrize("expr", [
        "contains(tolower(displayName),'jo')",  # nested function
        "not (x eq '1')",                       # not operator
        "x in ('a','b')",                       # in operator
    ])
    def test_unsupported_syntax_raises_typed_error(self, expr: str) -> None:
        """Unsupported-but-valid OData must surface as 400, not 500."""
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], expr)

    @pytest.mark.parametrize("expr", [
        "@@@",                  # nothing lexable at all
        "x eq 'Active",         # unterminated string literal
        "x eq '1' $$$",         # unlexable tail
    ])
    def test_unlexable_input_raises(self, expr: str) -> None:
        """Skipping junk characters would match every record, not none."""
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], expr)

    @pytest.mark.parametrize("expr", ["x eq '1' and", "x eq '1' or"])
    def test_dangling_conjunction_raises(self, expr: str) -> None:
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], expr)

    @pytest.mark.parametrize("expr", ["(x eq '1'(", "contains(x,'1'("])
    def test_open_paren_is_not_a_closer(self, expr: str) -> None:
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], expr)

    def test_empty_parentheses_raise(self) -> None:
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], "()")

    def test_deep_nesting_raises_rather_than_recursing(self) -> None:
        """A RecursionError is not an ODataFilterError, so it would be a 500."""
        expr = "(" * 300 + "x eq '1'" + ")" * 300
        with pytest.raises(ODataFilterError):
            apply_odata_filter([{"x": "1"}], expr)

    def test_error_is_a_valueerror(self) -> None:
        """Subclassing keeps any existing ``except ValueError`` callers working."""
        assert issubclass(ODataFilterError, ValueError)


class TestFiltering:
    """End-to-end behaviour over a record list."""

    RECORDS = [  # noqa: RUF012
        {"name": "SRV-CBWSEI", "os": "Windows"},
        {"name": "MAC-JARUHR", "os": "macOS"},
        {"name": "WS-FINANCE", "os": "Windows"},
    ]

    def test_contains_selects_matching_subset(self) -> None:
        got = apply_odata_filter(self.RECORDS, "contains(name,'WS')")
        assert [r["name"] for r in got] == ["SRV-CBWSEI", "WS-FINANCE"]

    def test_startswith_is_anchored(self) -> None:
        got = apply_odata_filter(self.RECORDS, "startswith(name,'WS')")
        assert [r["name"] for r in got] == ["WS-FINANCE"]

    def test_function_and_comparison_combined(self) -> None:
        got = apply_odata_filter(
            self.RECORDS, "contains(name,'WS') and os eq 'Windows'",
        )
        assert [r["name"] for r in got] == ["SRV-CBWSEI", "WS-FINANCE"]

    def test_result_is_a_new_list(self) -> None:
        """Filtering must not hand back the caller's own list."""
        assert apply_odata_filter(self.RECORDS, "") is not self.RECORDS
