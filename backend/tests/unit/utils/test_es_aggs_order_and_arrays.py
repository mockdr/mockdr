"""`terms.order`, and metrics over multi-valued fields.

Both were silently wrong rather than refused: an order was read past, and an
array counted as a single value (or, for a numeric metric, as none).
"""
from __future__ import annotations

from utils.es_aggs import apply_aggregations

RECORDS = [
    {"host": "b", "sev": 3, "tags": ["x", "y"], "ports": [22, 80]},
    {"host": "b", "sev": 1, "tags": ["x"], "ports": [443]},
    {"host": "a", "sev": 5, "tags": ["z", "x"], "ports": [80]},
    {"host": "c", "sev": 4},
    {"host": "c", "sev": 2},
    {"host": "c", "sev": 2},
]


def _keys(aggs: dict) -> list:
    out = apply_aggregations(RECORDS, {"t": aggs})
    return [(b["key"], b["doc_count"]) for b in out["t"]["buckets"]]


class TestTermsOrder:
    """`order` on a terms aggregation was ignored; `_count desc` came back always.

    The terms reference (search-aggregations-bucket-terms-aggregation.html,
    8.15) documents `_count`, `_key` and ordering by a metric
    sub-aggregation, singly or as a list, with `_key asc` breaking ties.
    """

    def test_default_is_count_desc_then_key(self) -> None:
        assert _keys({"terms": {"field": "host"}}) == [("c", 3), ("b", 2), ("a", 1)]

    def test_count_ascending(self) -> None:
        assert _keys({"terms": {"field": "host", "order": {"_count": "asc"}}}) == [
            ("a", 1), ("b", 2), ("c", 3)]

    def test_key_descending(self) -> None:
        assert _keys({"terms": {"field": "host", "order": {"_key": "desc"}}}) == [
            ("c", 3), ("b", 2), ("a", 1)]
        assert _keys({"terms": {"field": "host", "order": {"_key": "asc"}}}) == [
            ("a", 1), ("b", 2), ("c", 3)]

    def test_size_cuts_after_ordering(self) -> None:
        out = apply_aggregations(RECORDS, {"t": {"terms": {
            "field": "host", "size": 1, "order": {"_count": "asc"}}}})
        assert [b["key"] for b in out["t"]["buckets"]] == ["a"]
        assert out["t"]["sum_other_doc_count"] == 5

    def test_by_a_metric_sub_aggregation(self) -> None:
        aggs = {"terms": {"field": "host", "order": {"top": "desc"}},
                "aggs": {"top": {"max": {"field": "sev"}}}}
        assert [k for k, _ in _keys(aggs)] == ["a", "c", "b"]

    def test_by_one_stat_of_a_stats_sub_aggregation(self) -> None:
        aggs = {"terms": {"field": "host", "order": {"s.min": "asc"}},
                "aggs": {"s": {"stats": {"field": "sev"}}}}
        assert [k for k, _ in _keys(aggs)] == ["b", "c", "a"]

    def test_a_list_of_orders(self) -> None:
        aggs = {"terms": {"field": "tags", "order": [{"_count": "asc"}, {"_key": "desc"}]}}
        assert _keys(aggs) == [("z", 1), ("y", 1), ("x", 3)]

    def test_numeric_keys_order_as_numbers(self) -> None:
        aggs = {"terms": {"field": "ports", "order": {"_key": "asc"}}}
        assert [k for k, _ in _keys(aggs)] == [22, 80, 443]


class TestMetricsReadEveryValue:
    """An array was one value to `value_count` and `cardinality`, and none to `sum`.

    `value_count` counts values and `cardinality` distinct values, not
    documents (search-aggregations-metrics-valuecount-aggregation.html,
    -cardinality-aggregation.html, 8.15); a numeric metric reads every
    point a multi-valued field holds.
    """

    def test_value_count_counts_each_member(self) -> None:
        out = apply_aggregations(RECORDS, {"n": {"value_count": {"field": "tags"}}})
        assert out["n"]["value"] == 5

    def test_cardinality_counts_distinct_members(self) -> None:
        out = apply_aggregations(RECORDS, {"n": {"cardinality": {"field": "tags"}}})
        assert out["n"]["value"] == 3

    def test_numeric_metrics_read_each_member(self) -> None:
        out = apply_aggregations(RECORDS, {
            "s": {"sum": {"field": "ports"}}, "m": {"max": {"field": "ports"}},
            "st": {"stats": {"field": "ports"}},
        })
        assert out["s"]["value"] == 625.0
        assert out["m"]["value"] == 443.0
        assert out["st"]["count"] == 4
