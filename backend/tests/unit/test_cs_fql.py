"""Unit tests for the CrowdStrike FQL parser and filter engine.

Covers parsing, operator classification, value extraction, clause matching,
AND/OR grouping, and the full ``apply_fql`` pipeline.
"""
from __future__ import annotations

from utils.cs_fql import apply_fql, parse_fql

# ---------------------------------------------------------------------------
# parse_fql — basic parsing
# ---------------------------------------------------------------------------

class TestParseFql:
    """Tests for ``parse_fql`` string → clause list conversion."""

    def test_empty_string_returns_empty(self) -> None:
        assert parse_fql("") == []

    def test_whitespace_only_returns_empty(self) -> None:
        assert parse_fql("   ") == []

    def test_simple_equality(self) -> None:
        clauses = parse_fql("status:'normal'")
        assert len(clauses) == 1
        assert clauses[0].field == "status"
        assert clauses[0].operator == "eq"
        assert clauses[0].values == ["normal"]

    def test_bare_value_equality(self) -> None:
        """Unquoted values should be parsed correctly."""
        clauses = parse_fql("severity:50")
        assert len(clauses) == 1
        assert clauses[0].values == ["50"]

    def test_not_equals(self) -> None:
        clauses = parse_fql("status:!'offline'")
        assert len(clauses) == 1
        assert clauses[0].operator == "neq"
        assert clauses[0].values == ["offline"]

    def test_wildcard_detection(self) -> None:
        clauses = parse_fql("hostname:'*server*'")
        assert len(clauses) == 1
        assert clauses[0].operator == "wildcard"
        assert clauses[0].values == ["*server*"]

    def test_question_mark_wildcard(self) -> None:
        clauses = parse_fql("hostname:'server?'")
        assert clauses[0].operator == "wildcard"

    def test_in_list(self) -> None:
        clauses = parse_fql("platform_name:['Windows','Linux']")
        assert len(clauses) == 1
        assert clauses[0].operator == "in"
        assert clauses[0].values == ["Windows", "Linux"]

    def test_gte_operator(self) -> None:
        clauses = parse_fql("severity:>=50")
        assert clauses[0].operator == "gte"
        assert clauses[0].values == ["50"]

    def test_lte_operator(self) -> None:
        clauses = parse_fql("severity:<=30")
        assert clauses[0].operator == "lte"

    def test_gt_operator(self) -> None:
        clauses = parse_fql("severity:>50")
        assert clauses[0].operator == "gt"

    def test_lt_operator(self) -> None:
        clauses = parse_fql("severity:<10")
        assert clauses[0].operator == "lt"

    def test_and_conjunction(self) -> None:
        clauses = parse_fql("status:'normal'+platform_name:'Windows'")
        assert len(clauses) == 2
        assert clauses[0].field == "status"
        assert clauses[0].conjunction == "and"
        assert clauses[1].field == "platform_name"
        assert clauses[1].conjunction == "and"

    def test_or_conjunction(self) -> None:
        clauses = parse_fql("status:'normal',status:'containment_pending'")
        assert len(clauses) == 2
        assert clauses[0].conjunction == "and"  # first is always "and"
        assert clauses[1].conjunction == "or"

    def test_mixed_and_or(self) -> None:
        fql = "platform_name:'Windows'+status:'normal',status:'containment_pending'"
        clauses = parse_fql(fql)
        assert len(clauses) == 3
        assert clauses[0].conjunction == "and"
        assert clauses[1].conjunction == "and"
        assert clauses[2].conjunction == "or"

    def test_nested_dot_field(self) -> None:
        clauses = parse_fql("device.hostname:'myhost'")
        assert clauses[0].field == "device.hostname"

    def test_quotes_inside_brackets_preserved(self) -> None:
        """Commas inside brackets should not split into OR terms."""
        clauses = parse_fql("platform_name:['Windows','Linux','Mac']")
        assert len(clauses) == 1
        assert clauses[0].values == ["Windows", "Linux", "Mac"]


# ---------------------------------------------------------------------------
# apply_fql — filtering records
# ---------------------------------------------------------------------------

_RECORDS = [
    {"hostname": "LAPTOP-A", "platform_name": "Windows", "status": "normal", "severity": 50},
    {"hostname": "SRV-B", "platform_name": "Linux", "status": "normal", "severity": 80},
    {"hostname": "MAC-C", "platform_name": "Mac", "status": "offline", "severity": 20},
    {"hostname": "SRV-D", "platform_name": "Linux", "status": "containment_pending", "severity": 60},
]


class TestApplyFql:
    """Tests for ``apply_fql`` end-to-end filtering."""

    def test_no_filter_returns_all(self) -> None:
        assert len(apply_fql(_RECORDS, "")) == 4

    def test_equality_filter(self) -> None:
        result = apply_fql(_RECORDS, "platform_name:'Windows'")
        assert len(result) == 1
        assert result[0]["hostname"] == "LAPTOP-A"

    def test_neq_filter(self) -> None:
        result = apply_fql(_RECORDS, "status:!'normal'")
        hostnames = {r["hostname"] for r in result}
        assert hostnames == {"MAC-C", "SRV-D"}

    def test_wildcard_filter(self) -> None:
        result = apply_fql(_RECORDS, "hostname:'SRV*'")
        assert len(result) == 2

    def test_in_list_filter(self) -> None:
        result = apply_fql(_RECORDS, "platform_name:['Windows','Mac']")
        assert len(result) == 2

    def test_gte_numeric_filter(self) -> None:
        result = apply_fql(_RECORDS, "severity:>=60")
        assert len(result) == 2
        assert all(r["severity"] >= 60 for r in result)

    def test_lt_numeric_filter(self) -> None:
        result = apply_fql(_RECORDS, "severity:<50")
        assert len(result) == 1
        assert result[0]["severity"] == 20

    def test_and_filter(self) -> None:
        result = apply_fql(_RECORDS, "platform_name:'Linux'+status:'normal'")
        assert len(result) == 1
        assert result[0]["hostname"] == "SRV-B"

    def test_or_filter(self) -> None:
        result = apply_fql(_RECORDS, "status:'normal',status:'offline'")
        assert len(result) == 3

    def test_and_plus_or_filter(self) -> None:
        """AND between platform + OR between statuses."""
        fql = "platform_name:'Linux'+status:'normal',status:'containment_pending'"
        result = apply_fql(fql=fql, records=_RECORDS)
        hostnames = {r["hostname"] for r in result}
        assert hostnames == {"SRV-B", "SRV-D"}

    def test_nested_field_filter(self) -> None:
        records = [
            {"device": {"hostname": "A"}, "id": "1"},
            {"device": {"hostname": "B"}, "id": "2"},
        ]
        result = apply_fql(records, "device.hostname:'A'")
        assert len(result) == 1
        assert result[0]["id"] == "1"

    def test_missing_field_excluded(self) -> None:
        records = [{"name": "A"}, {"name": "B", "status": "ok"}]
        result = apply_fql(records, "status:'ok'")
        assert len(result) == 1

    def test_range_string_comparison_fallback(self) -> None:
        """Non-numeric values fall back to string comparison."""
        records = [
            {"ts": "2025-01-01T00:00:00Z"},
            {"ts": "2025-06-01T00:00:00Z"},
            {"ts": "2025-12-01T00:00:00Z"},
        ]
        result = apply_fql(records, "ts:>='2025-06-01T00:00:00Z'")
        assert len(result) == 2

    def test_range_none_field_excluded(self) -> None:
        records = [{"a": None}, {"a": 10}]
        result = apply_fql(records, "a:>=5")
        assert len(result) == 1
