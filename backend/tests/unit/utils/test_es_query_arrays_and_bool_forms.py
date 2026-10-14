"""Multi-valued fields in term-level queries, and the bool forms the reference uses.

Both were measured against the documents this mock serves itself: an alert
carries `event.category` as a list (`utils/es_ecs.py`), and the first example
on the bool reference page writes `"must"` as a single object.
"""
from __future__ import annotations

import pytest

from utils.es_query import apply_es_query, calculate_min_should_match


def _ids(records: list[dict], query: dict) -> list[str]:
    return [r["id"] for r in apply_es_query(records, {"query": query, "size": 100})]


ARRAYS = [
    {"id": "a", "event": {"category": ["process", "intrusion_detection"]},
     "port": [22, 8080], "seen": ["2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"]},
    {"id": "b", "event": {"category": ["network"]}, "port": [443],
     "seen": ["2026-03-01T00:00:00Z"]},
    {"id": "c", "event": {"category": "process"}, "port": 9000},
]


class TestTermLevelQueriesReadEveryValue:
    """`term`, `terms` and `range` compared a list field as one value.

    Lucene indexes each element of an array as its own term or point, so a
    document matches when any one of them does (mapping-types "Arrays",
    8.15). `prefix`, `wildcard` and `exists` already walked the values; these
    three did not, and `{"terms": {"event.category": ["process"]}}` found
    none of the mock's own alerts.
    """

    def test_term_matches_one_element(self) -> None:
        assert _ids(ARRAYS, {"term": {"event.category": "process"}}) == ["a", "c"]

    def test_term_with_a_value_object(self) -> None:
        assert _ids(ARRAYS, {"term": {"event.category": {"value": "network"}}}) == ["b"]

    def test_numeric_term_on_an_array(self) -> None:
        assert _ids(ARRAYS, {"term": {"port": 8080}}) == ["a"]

    def test_terms_matches_one_element(self) -> None:
        assert _ids(ARRAYS, {"terms": {"event.category": ["process"]}}) == ["a", "c"]

    def test_range_matches_when_one_value_is_inside(self) -> None:
        assert _ids(ARRAYS, {"range": {"port": {"gte": 8000, "lte": 8100}}}) == ["a"]

    def test_range_needs_one_value_inside_every_bound(self) -> None:
        # 22 is below 100 and 8080 is above 1000, but neither is between.
        assert _ids(ARRAYS, {"range": {"port": {"gte": 100, "lte": 1000}}}) == ["b"]

    def test_date_math_range_on_an_array(self) -> None:
        query = {"range": {"seen": {"gte": "2026-05-01T00:00:00Z||/d"}}}
        assert _ids(ARRAYS, query) == ["a"]


RECORDS = [
    {"id": "1", "host": "web01", "sev": "high", "tag": "x"},
    {"id": "2", "host": "web02", "sev": "low", "tag": "x"},
    {"id": "3", "host": "db01", "sev": "high", "tag": "y"},
]

SHOULDS = [{"term": {"host": "web01"}}, {"term": {"sev": "high"}}, {"term": {"tag": "x"}}]


class TestBoolTakesASingleObject:
    """`"must": {"term": ...}` was refused because the object's keys were iterated.

    The bool reference (query-dsl-bool-query.html, 8.15) writes `must` as a
    single object in its first example; every arm takes either form.
    """

    def test_every_arm_takes_an_object(self) -> None:
        query = {"bool": {
            "must": {"term": {"tag": "x"}},
            "filter": {"term": {"sev": "high"}},
            "must_not": {"term": {"host": "web02"}},
            "should": {"term": {"host": "web01"}},
        }}
        assert _ids(RECORDS, query) == ["1"]

    def test_a_single_should_alone_still_requires_its_match(self) -> None:
        assert _ids(RECORDS, {"bool": {"should": {"term": {"host": "db01"}}}}) == ["3"]


class TestStringMinimumShouldMatch:
    """A string `minimum_should_match` on bool raised TypeError: a 500.

    Every form on query-dsl-minimum-should-match.html (8.15) is a string but
    the plain integer, and `match` already read them; bool compared the
    string against an int. The arithmetic is Lucene's
    `Queries.calculateMinShouldMatch` (Elasticsearch v8.15.0).
    """

    # Record 1 matches all three shoulds; records 2 and 3 match one each.
    @pytest.mark.parametrize(("spec", "expected"), [
        ("1", ["1", "2", "3"]),
        ("2", ["1"]),
        ("-1", ["1"]),               # 3 - 1
        ("66%", ["1", "2", "3"]),    # 1.98 truncates to 1
        ("-34%", ["1"]),             # 3 + trunc(-1.02)
        ("3<90%", ["1"]),            # not more than three clauses: all of them
        ("2<-25%", ["1"]),           # more than two: 3 + trunc(-0.75) = 3
    ])
    def test_the_documented_forms(self, spec: str, expected: list[str]) -> None:
        query = {"bool": {"should": SHOULDS, "minimum_should_match": spec}}
        assert _ids(RECORDS, query) == expected

    @pytest.mark.parametrize(("optional", "spec", "expected"), [
        (3, "2", 2), (3, 2, 2), (3, "-1", 2), (4, "75%", 3), (4, "-25%", 3),
        (3, "50%", 1), (3, "-50%", 2), (3, "3<90%", 3), (10, "3<90%", 9),
        (2, "2<-25% 9<-3", 2), (5, "2<-25% 9<-3", 4), (12, "2<-25% 9<-3", 9),
        (3, "5", 5), (3, "-5", 0), (10, "30%", 3),
    ])
    def test_the_arithmetic(self, optional: int, spec: object, expected: int) -> None:
        assert calculate_min_should_match(optional, spec) == expected

    def test_more_required_than_there_are_matches_nothing(self) -> None:
        query = {"bool": {"should": SHOULDS, "minimum_should_match": "4"}}
        assert _ids(RECORDS, query) == []

    def test_a_string_beside_a_must(self) -> None:
        query = {"bool": {"must": {"term": {"tag": "x"}},
                          "should": [{"term": {"sev": "high"}}],
                          "minimum_should_match": "1"}}
        assert _ids(RECORDS, query) == ["1"]

    def test_zero_on_shoulds_alone_still_requires_one(self) -> None:
        """Nothing required, so the bool is a disjunction (Lucene BooleanQuery)."""
        query = {"bool": {"should": [{"term": {"host": "db01"}}],
                          "minimum_should_match": "-1"}}
        assert _ids(RECORDS, query) == ["3"]
