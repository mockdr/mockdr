"""Aggregation shapes, measured against Elasticsearch 8.15.

The same five documents were indexed into a real cluster and the same 29
aggregations run against both engines. Four families of difference came out
of that, all of which reach a client as a wrong chart rather than an error:

* ``date_histogram`` left out every interval with no documents, so a series
  plotted from the response skipped quiet days instead of drawing them at
  zero;
* a calendar interval was a fixed span of seconds, so ``1M`` meant 30 days
  and ``1w`` a week beginning on a Thursday — the weekday the epoch fell on;
* ``key_as_string`` was ``+00:00`` where Elasticsearch writes ``.000Z``;
* every numeric metric was shrunk to an int, so an average of exactly 30 came
  back as ``30`` where Elasticsearch sends the double ``30.0``.
"""
import pytest

from utils.es_aggs import ESAggregationError, apply_aggregations

DOCS = [
    {"name": "a", "@timestamp": "2026-08-01T04:00:00Z", "host": "srv-1", "sev": 10},
    {"name": "b", "@timestamp": "2026-08-01T20:00:00Z", "host": "srv-1", "sev": 20},
    {"name": "c", "@timestamp": "2026-08-03T09:00:00Z", "host": "srv-2", "sev": 30},
    {"name": "d", "@timestamp": "2026-08-10T09:00:00Z", "host": "srv-3", "sev": 40},
    {"name": "e", "@timestamp": "2026-08-10T09:00:00Z", "host": "srv-2", "sev": 50},
]


def buckets(body: dict) -> list[tuple]:
    """The ``(key_as_string, doc_count)`` pairs one aggregation produces."""
    result = apply_aggregations(list(DOCS), {"p": body})["p"]["buckets"]
    return [(b.get("key_as_string", b.get("key")), b["doc_count"]) for b in result]


class TestDateHistogram:
    """Bucketing by time, including the intervals nothing landed in."""

    def test_empty_intervals_are_drawn_at_zero(self) -> None:
        assert buckets({"date_histogram": {
            "field": "@timestamp", "calendar_interval": "1d",
        }}) == [
            ("2026-08-01T00:00:00.000Z", 2),
            ("2026-08-02T00:00:00.000Z", 0),
            ("2026-08-03T00:00:00.000Z", 1),
            ("2026-08-04T00:00:00.000Z", 0),
            ("2026-08-05T00:00:00.000Z", 0),
            ("2026-08-06T00:00:00.000Z", 0),
            ("2026-08-07T00:00:00.000Z", 0),
            ("2026-08-08T00:00:00.000Z", 0),
            ("2026-08-09T00:00:00.000Z", 0),
            ("2026-08-10T00:00:00.000Z", 2),
        ]

    def test_min_doc_count_suppresses_them(self) -> None:
        assert buckets({"date_histogram": {
            "field": "@timestamp", "calendar_interval": "1d", "min_doc_count": 1,
        }}) == [
            ("2026-08-01T00:00:00.000Z", 2),
            ("2026-08-03T00:00:00.000Z", 1),
            ("2026-08-10T00:00:00.000Z", 2),
        ]

    def test_a_calendar_week_begins_on_monday(self) -> None:
        # 27 July 2026 is a Monday. Anchoring weeks on the epoch would put
        # them on a Thursday, which is the weekday 1 January 1970 fell on.
        assert buckets({"date_histogram": {
            "field": "@timestamp", "calendar_interval": "1w",
        }}) == [
            ("2026-07-27T00:00:00.000Z", 2),
            ("2026-08-03T00:00:00.000Z", 1),
            ("2026-08-10T00:00:00.000Z", 2),
        ]

    def test_a_calendar_month_is_a_month(self) -> None:
        assert buckets({"date_histogram": {
            "field": "@timestamp", "calendar_interval": "1M",
        }}) == [("2026-08-01T00:00:00.000Z", 5)]

    def test_a_quarter_starts_where_the_quarter_does(self) -> None:
        assert buckets({"date_histogram": {
            "field": "@timestamp", "calendar_interval": "quarter",
        }}) == [("2026-07-01T00:00:00.000Z", 5)]

    def test_a_fixed_interval_is_anchored_on_the_epoch(self) -> None:
        # 36 hours divides the epoch, not the data: the first bucket starts
        # before the first document.
        assert buckets({"date_histogram": {
            "field": "@timestamp", "fixed_interval": "36h",
        }})[0] == ("2026-07-31T12:00:00.000Z", 2)

    def test_a_time_zone_moves_the_boundaries_and_the_rendering(self) -> None:
        first = buckets({"date_histogram": {
            "field": "@timestamp", "calendar_interval": "1d",
            "time_zone": "Europe/Berlin",
        }})[0]
        assert first == ("2026-08-01T00:00:00.000+02:00", 2)

    def test_the_removed_interval_parameter_is_refused(self) -> None:
        with pytest.raises(ESAggregationError, match=r"unknown field \[interval\]") as caught:
            apply_aggregations(list(DOCS), {"p": {"date_histogram": {
                "field": "@timestamp", "interval": "1d",
            }}})
        assert caught.value.es_type == "x_content_parse_exception"


class TestMetricTypes:
    """Elasticsearch sends a double for every numeric metric."""

    @pytest.mark.parametrize(("agg", "expected"), [
        ({"avg": {"field": "sev"}}, 30.0),
        ({"min": {"field": "sev"}}, 10.0),
        ({"max": {"field": "sev"}}, 50.0),
        ({"sum": {"field": "sev"}}, 150.0),
    ])
    def test_a_metric_that_divides_evenly_is_still_a_double(
        self, agg: dict, expected: float,
    ) -> None:
        value = apply_aggregations(list(DOCS), {"m": agg})["m"]["value"]
        assert isinstance(value, float)
        assert value == expected

    def test_stats_reports_a_count_as_an_int_and_the_rest_as_doubles(self) -> None:
        stats = apply_aggregations(list(DOCS), {"s": {"stats": {"field": "sev"}}})["s"]
        assert stats == {"count": 5, "min": 10.0, "max": 50.0, "avg": 30.0, "sum": 150.0}
        assert isinstance(stats["count"], int)
        assert all(isinstance(stats[k], float) for k in ("min", "max", "avg", "sum"))

    def test_counting_aggregations_stay_ints(self) -> None:
        result = apply_aggregations(list(DOCS), {
            "c": {"cardinality": {"field": "host"}},
            "v": {"value_count": {"field": "sev"}},
        })
        assert result == {"c": {"value": 3}, "v": {"value": 5}}

    def test_a_sum_over_nothing_is_zero_and_the_rest_are_null(self) -> None:
        result = apply_aggregations(list(DOCS), {
            "s": {"sum": {"field": "absent"}}, "a": {"avg": {"field": "absent"}},
        })
        assert result == {"s": {"value": 0.0}, "a": {"value": None}}


class TestBucketKeys:
    """The strings and numbers a bucket is keyed by."""

    def test_a_histogram_key_is_a_double(self) -> None:
        keys = [k for k, _ in buckets({"histogram": {"field": "sev", "interval": 20}})]
        assert keys == [0.0, 20.0, 40.0]
        assert all(isinstance(k, float) for k in keys)

    def test_range_bucket_keys_render_their_bounds_as_doubles(self) -> None:
        result = apply_aggregations(list(DOCS), {"r": {"range": {
            "field": "sev", "ranges": [{"to": 25}, {"from": 25, "to": 45}, {"from": 45}],
        }}})["r"]["buckets"]
        assert [b["key"] for b in result] == ["*-25.0", "25.0-45.0", "45.0-*"]
