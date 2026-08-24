"""Date math, Lucene ranges and ``search_after`` — the time filter every client sends.

Every expectation here was taken from Elasticsearch 8.15 itself: the same six
documents were indexed into a real cluster and the same queries run against
both engines, and each case below is what the real one answered. A range
bound written as ``now-30d`` used to be compared as a *string*
(``"2026-08-06T…" >= "now-30d"`` is false for every document), so the mock
answered ``200`` with an empty result set for the one filter that appears in
essentially every Kibana dashboard and detection rule.
"""
from datetime import UTC, datetime

import pytest

from utils.es_datemath import DateMathError, is_date_math, parse_datetime
from utils.es_datemath import resolve as resolve_date_math
from utils.es_query import (
    ESQueryError,
    apply_es_query,
    apply_es_sort,
    build_predicate,
    doc_positions,
    emits_sort_values,
    parse_sort_keys,
    validate_search_body,
    wrap_as_hits,
)

#: A fixed "now" so the expectations are arithmetic, not a race with the clock.
NOW = datetime(2026, 8, 24, 13, 30, 15, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``now`` to the instant these expectations were measured at.

    The documents below are absolute, so a moving clock would make the
    windows drift and the suite start failing on a calendar boundary rather
    than on a defect.
    """
    monkeypatch.setattr("utils.es_datemath.current_time", lambda: NOW)


def at(text: str) -> dict:
    """One document, timestamped."""
    return {"@timestamp": text, "name": text}


DOCS = [
    at("2026-08-24T12:30:15.000Z"),   # an hour ago
    at("2026-08-24T00:00:00.000Z"),   # midnight today
    at("2026-08-21T13:30:15.000Z"),   # three days ago
    at("2026-08-04T13:30:15.000Z"),   # twenty days ago
    at("2026-07-15T13:30:15.000Z"),   # forty days ago
    at("2024-08-25T13:30:15.000Z"),   # two years ago
]


def names(query: dict, docs: list[dict] | None = None) -> list[str]:
    """The documents a query matches, by name."""
    predicate = build_predicate(query)
    return [d["name"] for d in (docs if docs is not None else DOCS) if predicate(d)]


class TestResolution:
    """The grammar itself: anchors, offsets, rounding."""

    @pytest.mark.parametrize(("expression", "expected"), [
        ("now", "2026-08-24T13:30:15+00:00"),
        ("now-30d", "2026-07-25T13:30:15+00:00"),
        ("now+1h", "2026-08-24T14:30:15+00:00"),
        ("now-1M", "2026-07-24T13:30:15+00:00"),
        ("now-1y", "2025-08-24T13:30:15+00:00"),
        ("now/d", "2026-08-24T00:00:00+00:00"),
        ("now/h", "2026-08-24T13:00:00+00:00"),
        ("now/M", "2026-08-01T00:00:00+00:00"),
        ("now/y", "2026-01-01T00:00:00+00:00"),
        # 24 August 2026 is a Monday, so the week already starts there.
        ("now/w", "2026-08-24T00:00:00+00:00"),
        ("now-1d/w", "2026-08-17T00:00:00+00:00"),
        # Operations apply left to right: round to the day, then add.
        ("now-7d/d+2h", "2026-08-17T02:00:00+00:00"),
        ("2014-11-18T12:00:00Z||/M", "2014-11-01T00:00:00+00:00"),
        ("2014-11-18||+1M", "2014-12-18T00:00:00+00:00"),
    ])
    def test_expression_resolves(self, expression: str, expected: str) -> None:
        assert resolve_date_math(expression, now=NOW).isoformat() == expected

    def test_month_arithmetic_clamps_the_day(self) -> None:
        # java.time gives 28 February, not 3 March — verified against 8.15.
        resolved = resolve_date_math("2014-03-31||-1M", now=NOW)
        assert resolved.isoformat() == "2014-02-28T00:00:00+00:00"

    def test_rounding_up_lands_on_the_last_millisecond(self) -> None:
        resolved = resolve_date_math("now/d", now=NOW, round_up=True)
        assert resolved.isoformat() == "2026-08-24T23:59:59.999000+00:00"

    def test_a_timezone_moves_the_rounding_boundary(self) -> None:
        # Midnight in Berlin is 22:00 UTC the previous day (CEST, +02:00).
        resolved = resolve_date_math("now/d", now=NOW, time_zone="Europe/Berlin")
        assert resolved.isoformat() == "2026-08-23T22:00:00+00:00"

    def test_a_fixed_offset_timezone_is_accepted(self) -> None:
        resolved = resolve_date_math("now/d", now=NOW, time_zone="+02:00")
        assert resolved.isoformat() == "2026-08-23T22:00:00+00:00"

    @pytest.mark.parametrize("expression", ["2026-08-24T00:00:00Z", "12345", ""])
    def test_a_plain_timestamp_is_not_date_math(self, expression: str) -> None:
        assert not is_date_math(expression)
        assert resolve_date_math(expression, now=NOW) is None

    def test_an_unknown_unit_is_refused_by_name(self) -> None:
        with pytest.raises(DateMathError, match=r"unit \[q\] not supported"):
            resolve_date_math("now-30q", now=NOW)

    @pytest.mark.parametrize("value", [
        "2026-08-24T13:30:15.000Z", "2026-08-24T13:30:15+00:00", "2026-08-24",
    ])
    def test_stored_values_parse_in_the_forms_a_date_field_accepts(self, value: str) -> None:
        assert parse_datetime(value) is not None

    def test_epoch_millis_parse_as_the_instant_they_name(self) -> None:
        assert parse_datetime(1787574615000) == datetime(2026, 8, 24, 12, 30, 15, tzinfo=UTC)

    @pytest.mark.parametrize("value", ["SERVER-1", None, True, ""])
    def test_a_value_that_is_not_a_date_stays_none(self, value: object) -> None:
        assert parse_datetime(value) is None


class TestRangeQueries:
    """What a range clause matches, against the six documents above."""

    def test_relative_window_matches_instead_of_nothing(self) -> None:
        assert names({"range": {"@timestamp": {"gte": "now-30d"}}}) == [
            "2026-08-24T12:30:15.000Z", "2026-08-24T00:00:00.000Z",
            "2026-08-21T13:30:15.000Z", "2026-08-04T13:30:15.000Z",
        ]

    def test_both_ends_of_a_window_apply(self) -> None:
        matched = names({"range": {"@timestamp": {"gte": "now-30d", "lt": "now-10d"}}})
        assert matched == ["2026-08-04T13:30:15.000Z"]

    def test_gte_rounds_down_and_includes_the_whole_day(self) -> None:
        assert names({"range": {"@timestamp": {"gte": "now/d"}}}) == [
            "2026-08-24T12:30:15.000Z", "2026-08-24T00:00:00.000Z",
        ]

    def test_lte_rounds_up_and_includes_the_whole_day(self) -> None:
        # Every document, because today's last millisecond is after them all.
        assert len(names({"range": {"@timestamp": {"lte": "now/d"}}})) == len(DOCS)

    def test_gt_rounds_up_and_excludes_the_whole_day(self) -> None:
        assert names({"range": {"@timestamp": {"gt": "now/d"}}}) == []

    def test_lt_rounds_down_and_excludes_the_whole_day(self) -> None:
        assert names({"range": {"@timestamp": {"lt": "now/d"}}}) == [
            "2026-08-21T13:30:15.000Z", "2026-08-04T13:30:15.000Z",
            "2026-07-15T13:30:15.000Z", "2024-08-25T13:30:15.000Z",
        ]

    def test_an_absolute_bound_still_compares(self) -> None:
        matched = names({"range": {"@timestamp": {"gte": "2026-08-20T00:00:00.000Z"}}})
        assert len(matched) == 3

    def test_a_numeric_range_is_untouched_by_date_handling(self) -> None:
        docs = [{"name": "low", "score": 10}, {"name": "high", "score": 90}]
        assert names({"range": {"score": {"gte": 50}}}, docs) == ["high"]

    def test_a_document_without_the_field_cannot_be_in_the_window(self) -> None:
        assert names({"range": {"@timestamp": {"gte": "now-30d"}}}, [{"name": "x"}]) == []

    def test_a_malformed_expression_is_a_query_error_not_an_empty_page(self) -> None:
        with pytest.raises(ESQueryError, match=r"unit \[q\] not supported"):
            build_predicate({"range": {"@timestamp": {"gte": "now-30q"}}})

    def test_format_and_boost_are_ignored_rather_than_read_as_bounds(self) -> None:
        query = {"range": {"@timestamp": {
            "gte": "now-30d", "format": "strict_date_optional_time", "boost": 2,
        }}}
        assert len(names(query)) == 4


class TestQueryStringRanges:
    """Lucene's own range spellings, which Kibana and detection rules send."""

    def test_inclusive_brackets_include_both_bounds(self) -> None:
        assert names({"query_string": {"query": "@timestamp:[now-30d TO now]"}}) == [
            "2026-08-24T12:30:15.000Z", "2026-08-24T00:00:00.000Z",
            "2026-08-21T13:30:15.000Z", "2026-08-04T13:30:15.000Z",
        ]

    def test_braces_exclude_the_bounds(self) -> None:
        docs = [at("2026-08-10T00:00:00.000Z"), at("2026-08-11T00:00:00.000Z")]
        query = {"query_string": {
            "query": "@timestamp:{2026-08-10T00:00:00.000Z TO 2026-08-12T00:00:00.000Z}",
        }}
        assert names(query, docs) == ["2026-08-11T00:00:00.000Z"]

    def test_the_comparison_shorthand_bounds_one_side(self) -> None:
        assert len(names({"query_string": {"query": "@timestamp:>=now-30d"}})) == 4
        assert len(names({"query_string": {"query": "@timestamp:<now-30d"}})) == 2

    def test_a_star_bound_is_an_existence_check(self) -> None:
        docs = [{"name": "with", "host": "a"}, {"name": "without"}]
        assert names({"query_string": {"query": "host:[* TO *]"}}, docs) == ["with"]

    def test_an_at_prefixed_field_is_a_field_and_not_a_bare_word(self) -> None:
        # `@timestamp:…` used to tokenise as a bare word and search every
        # field, so it matched documents that merely mentioned the value.
        docs = [{"name": "hit", "@timestamp": "2026-08-24T00:00:00.000Z"},
                {"name": "miss", "other": "2026-08-24T00:00:00.000Z"}]
        query = {"query_string": {"query": "@timestamp:2026-08-24T00:00:00.000Z"}}
        assert names(query, docs) == ["hit"]


class TestSortValuesAndSearchAfter:
    """Deep paging: without per-hit sort values no client can do it at all."""

    def test_a_sorted_hit_carries_its_sort_values(self) -> None:
        keys = parse_sort_keys([{"@timestamp": "desc"}])
        hit = wrap_as_hits([DOCS[0]], sort_keys=keys)[0]
        # A date sorts on epoch milliseconds, as its doc values do.
        assert hit["sort"] == [1787574615000]

    def test_a_sorted_search_is_not_a_scored_one(self) -> None:
        keys = parse_sort_keys([{"@timestamp": "desc"}])
        assert wrap_as_hits([DOCS[0]], sort_keys=keys)[0]["_score"] is None
        assert wrap_as_hits([DOCS[0]])[0]["_score"] == 1.0

    def test_a_keyword_sorts_on_itself(self) -> None:
        keys = parse_sort_keys([{"name": "asc"}])
        assert wrap_as_hits([{"name": "SERVER-1"}], sort_keys=keys)[0]["sort"] == ["SERVER-1"]

    def test_doc_order_sorts_on_the_documents_position(self) -> None:
        keys = parse_sort_keys(["_doc"])
        positions = doc_positions(DOCS)
        hit = wrap_as_hits([DOCS[2]], sort_keys=keys, positions=positions)[0]
        assert hit["sort"] == [2]

    def test_sorting_only_by_score_emits_no_sort_values(self) -> None:
        assert not emits_sort_values(parse_sort_keys(["_score"]))
        assert emits_sort_values(parse_sort_keys([{"@timestamp": "desc"}]))

    def test_paging_with_search_after_walks_the_whole_result(self) -> None:
        seen: list[str] = []
        after: list | None = None
        for _ in range(len(DOCS) + 1):
            body: dict = {"size": 2, "sort": [{"@timestamp": "desc"}, {"name": "asc"}]}
            if after is not None:
                body["search_after"] = after
            page = apply_es_query(list(DOCS), body)
            if not page:
                break
            keys = parse_sort_keys(body["sort"])
            hits = wrap_as_hits(page, sort_keys=keys)
            seen += [h["_source"]["name"] for h in hits]
            after = hits[-1]["sort"]
        # Every document exactly once, newest first, and the walk terminates.
        assert seen == [d["name"] for d in DOCS]

    def test_search_after_excludes_the_document_it_names(self) -> None:
        body = {
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
            "search_after": [1787574615000],
        }
        page = apply_es_query(list(DOCS), body)
        assert DOCS[0] not in page

    def test_search_after_without_a_sort_is_refused(self) -> None:
        with pytest.raises(ESQueryError, match="Sort must contain at least one field"):
            validate_search_body({"search_after": [1]})

    def test_search_after_of_the_wrong_length_is_refused(self) -> None:
        with pytest.raises(ESQueryError, match=r"search_after has 2 value\(s\) but sort has 1"):
            validate_search_body({"sort": [{"@timestamp": "desc"}], "search_after": [1, 2]})


class TestMissingValueOrdering:
    """A document without the sort field goes last, whichever way the sort runs.

    Elasticsearch's ``missing`` defaults to ``_last`` and it means last in
    *both* directions. Sorting descending used to reverse that group along
    with everything else, so a "newest first" search led with the documents
    that carry no timestamp at all — the ones a client is least interested in
    and most likely to mistake for the newest.
    """

    RECORDS = [
        {"name": "none"},
        {"name": "old", "@timestamp": "2026-01-01T00:00:00.000Z"},
        {"name": "new", "@timestamp": "2026-06-01T00:00:00.000Z"},
    ]

    def _ordered(self, spec: list) -> list[str]:
        return [r["name"] for r in apply_es_sort(list(self.RECORDS), spec)]

    def test_descending_keeps_documents_without_the_field_last(self) -> None:
        assert self._ordered([{"@timestamp": "desc"}]) == ["new", "old", "none"]

    def test_ascending_keeps_them_last_too(self) -> None:
        assert self._ordered([{"@timestamp": "asc"}]) == ["old", "new", "none"]

    def test_missing_first_puts_them_at_the_front(self) -> None:
        spec = [{"@timestamp": {"order": "desc", "missing": "_first"}}]
        assert self._ordered(spec) == ["none", "new", "old"]

    def test_missing_first_ascending(self) -> None:
        spec = [{"@timestamp": {"order": "asc", "missing": "_first"}}]
        assert self._ordered(spec) == ["none", "old", "new"]
