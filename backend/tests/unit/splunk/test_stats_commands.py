"""``stats`` and ``streamstats``, measured against Splunk 10.4.2.

62 searches were run against a real instance and this one and the rows
compared. The differences that turned out to be defects here are below; the
two worth naming are:

* **An aggregation with nothing to compute writes no field.** `sum` over a
  text field, `avg` over a field the rows do not have, `values` over the
  same — splunkd leaves the field out of the row entirely, and gives no row
  at all when there is no `by` and nothing could be computed. The mock wrote
  `0` and `""`, so a client reading `sum(bytes)` got a number here and no
  field in production.
* **`median` is not `perc50`.** With an even number of values splunkd
  averages the middle pair and rounds an exact half *up*: the median of 1
  and 2 is 2, of 1 and 4 is 3, of 1.2 and 1.4 is 1.3.
"""
import pytest

from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl

#: Four rows, two groups, one numeric field — the shape every measurement
#: below was taken with.
ROWS = '| makeresults format=csv data="n,g\n1,a\n2,b\n3,a\n4,b" '


def run(spl: str, rows: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    """Run a pipeline, returning its rows and messages."""
    return execute_pipeline(list(rows or []), parse_spl(spl))


def out(spl: str, rows: list[dict] | None = None) -> list[dict]:
    """The rows a pipeline produces, failing loudly if it did not run."""
    produced, messages = run(spl, rows)
    fatal = [m for m in messages if m["type"] == "FATAL"]
    if fatal:
        pytest.fail(f"unexpected failure: {fatal[0]['text']}")
    return produced


def failure(spl: str) -> str:
    """The FATAL text a pipeline produces."""
    _rows, messages = run(spl)
    assert messages, "expected the search to fail"
    return messages[0]["text"]


class TestNothingToCompute:
    """What splunkd writes when an aggregation has no value."""

    def test_a_sum_over_text_writes_no_field(self) -> None:
        assert out(ROWS + "| stats count, sum(g)") == [{"count": 4}]

    def test_a_group_keeps_its_key_and_loses_the_field(self) -> None:
        assert out(ROWS + "| stats sum(g) by n") == [
            {"n": "1"}, {"n": "2"}, {"n": "3"}, {"n": "4"},
        ]

    def test_nothing_computable_and_no_grouping_is_no_row(self) -> None:
        assert out(ROWS + "| stats sum(g)") == []
        assert out(ROWS + "| stats first(nosuchfield) as f, values(nosuchfield) as v") == []

    def test_count_over_an_empty_result_set_is_still_a_row(self) -> None:
        assert out("| makeresults count=0 | stats count") == [{"count": 0}]

    def test_but_a_sum_over_one_is_not(self) -> None:
        assert out("| makeresults count=0 | stats sum(n) as s") == []

    def test_a_count_of_a_field_the_rows_lack_is_zero(self) -> None:
        assert out(ROWS + "| stats count(nosuchfield) as c") == [{"c": 0}]
        assert out(ROWS + "| stats dc(nosuchfield) as d") == [{"d": 0}]


class TestValueTypes:
    """Text where a number was expected, and the other way round."""

    def test_min_and_max_fall_back_to_text(self) -> None:
        rows = out('| makeresults format=csv data="v\na\nb" | stats max(v) as mx, min(v) as mn')
        assert rows == [{"mx": "b", "mn": "a"}]

    def test_a_number_wins_over_text_in_the_same_field(self) -> None:
        # Over 1, "a" and 3, `max` is 3 rather than the string.
        rows = out('| makeresults format=csv data="v\n1\na\n3" | stats max(v) as mx, sum(v) as s')
        assert rows == [{"mx": 3, "s": 4}]

    def test_an_empty_string_is_a_value(self) -> None:
        rows = out('| makeresults count=2 | eval x="" | stats count(x) as c, values(x) as v')
        assert rows == [{"c": 2, "v": [""]}]

    def test_an_empty_cell_in_inline_data_is_not(self) -> None:
        rows = out('| makeresults format=csv data="v,w\n1,x\n,y\n3,z" | stats count(v) as c')
        assert rows == [{"c": 2}]


class TestMedian:
    """The middle value, and the pair that has no middle."""

    @pytest.mark.parametrize(("data", "expected"), [
        ("1\n2", 2), ("1\n4", 3), ("2\n3", 3), ("0\n1", 1),
        ("1\n2\n3\n4", 3), ("10\n20\n30\n40\n50\n60", 35),
        ("1\n2\n3", 2), ("1\n2\n3\n4\n5", 3),
    ])
    def test_an_exact_half_rounds_up(self, data: str, expected: float) -> None:
        rows = out(f'| makeresults format=csv data="v\n{data}" | stats median(v) as m')
        assert rows == [{"m": expected}]

    def test_a_middle_that_is_not_a_half_is_left_alone(self) -> None:
        rows = out('| makeresults format=csv data="v\n1.2\n1.4" | stats median(v) as m')
        assert rows[0]["m"] == pytest.approx(1.3)

    def test_perc50_interpolates_without_the_rounding(self) -> None:
        rows = out('| makeresults format=csv data="v\n1\n2\n3\n4" | stats perc50(v) as p, p90(v) as q')
        assert rows[0]["p"] == pytest.approx(2.5)
        assert rows[0]["q"] == pytest.approx(3.7)


class TestArguments:
    """A token a stats-like command cannot read."""

    def test_an_unknown_function_is_refused_by_name(self) -> None:
        assert failure(ROWS + "| stats nosuchfunc(n)") == (
            "Error in 'stats' command: The argument 'nosuchfunc(n)' is invalid."
        )

    def test_an_unknown_option_is_refused_too(self) -> None:
        # It was ignored here, so the command ran with a different meaning
        # than the one asked for.
        assert failure(ROWS + "| stats count nosucharg=1") == (
            "Error in 'stats' command: The argument 'nosucharg=1' is invalid."
        )

    def test_streamstats_says_the_same(self) -> None:
        assert failure(ROWS + "| streamstats nosuchfunc(n)") == (
            "Error in 'streamstats' command: The argument 'nosuchfunc(n)' is invalid."
        )

    def test_an_alias_stops_at_the_comma(self) -> None:
        rows = out(ROWS + "| stats perc50(n) as p, avg(n) as a")
        assert set(rows[0]) == {"p", "a"}


class TestStreamstats:
    """stats over the rows seen so far, added to each row as it passes."""

    def counts(self, spl: str) -> list[object]:
        return [row.get("count", row.get("c", row.get("s"))) for row in out(ROWS + spl)]

    def test_a_running_count(self) -> None:
        assert self.counts("| streamstats count") == [1, 2, 3, 4]

    def test_a_running_count_per_group(self) -> None:
        assert self.counts("| streamstats count by g") == [1, 1, 2, 2]

    def test_a_running_sum(self) -> None:
        assert self.counts("| streamstats sum(n) as s") == [1, 3, 6, 10]

    def test_the_row_keeps_its_own_fields(self) -> None:
        assert out(ROWS + "| streamstats count")[0] == {"n": "1", "g": "a", "count": 1}

    def test_a_window_looks_at_the_last_n_rows(self) -> None:
        assert self.counts("| streamstats count window=2") == [1, 2, 2, 2]

    def test_window_zero_is_no_window_at_all(self) -> None:
        assert self.counts("| streamstats count window=0") == [1, 2, 3, 4]

    def test_current_false_looks_only_at_the_rows_before(self) -> None:
        assert self.counts("| streamstats current=f count") == [0, 1, 2, 3]

    def test_and_leaves_the_first_row_without_a_sum(self) -> None:
        # Nothing to sum yet, so the field is not written — the same rule as
        # `stats` follows.
        rows = out(ROWS + "| streamstats current=false sum(n) as s")
        assert "s" not in rows[0]
        assert [r.get("s") for r in rows[1:]] == [1, 3, 6]

    def test_a_window_and_a_grouping_together(self) -> None:
        assert self.counts("| streamstats count as c by g window=1") == [1, 1, 1, 1]

    def test_reset_on_change_starts_again_when_the_group_changes(self) -> None:
        assert self.counts("| streamstats count reset_on_change=true by g") == [1, 1, 1, 1]

    def test_reset_before_starts_again_at_the_matching_row(self) -> None:
        assert self.counts('| streamstats reset_before="n>2" count') == [1, 2, 1, 1]

    def test_reset_after_starts_again_below_it(self) -> None:
        assert self.counts('| streamstats reset_after="n>2" count') == [1, 2, 3, 1]

    def test_a_row_without_the_by_field_is_left_alone(self) -> None:
        assert out(ROWS + "| streamstats count by nosuchfield") == [
            {"n": "1", "g": "a"}, {"n": "2", "g": "b"},
            {"n": "3", "g": "a"}, {"n": "4", "g": "b"},
        ]

    def test_multivalue_statistics_accumulate(self) -> None:
        rows = out(ROWS + "| streamstats values(g) as v")
        assert [r["v"] for r in rows] == [["a"], ["a", "b"], ["a", "b"], ["a", "b"]]

    def test_a_time_window_holds_what_falls_inside_it(self) -> None:
        events = [{"_time": 1787500000.0 + 3600 * i, "sev": 10} for i in range(5)]
        # An hour apart, so a one-hour window holds only the event itself:
        # the far edge is open.
        assert [r["count"] for r in out("search * | streamstats time_window=1h count", events)] == [1] * 5
        assert [r["count"] for r in out("search * | streamstats time_window=2h count", events)] == [1, 2, 2, 2, 2]

    def test_a_time_window_needs_rows_in_time_order(self) -> None:
        assert failure(ROWS + "| streamstats time_window=1h count") == (
            "Error in 'streamstats' command: time_window can only be used on "
            "input that is sorted in time order (both ascending and "
            "descending order are ok)."
        )


class TestTheFieldBlock:
    """Which columns the response declares, and in what order.

    Measured against Splunk 10.4.2: the block is alphabetical unless a
    command in the pipeline *built* the row — `table`, `fields`, `stats`,
    `timechart`, `top`, `rare` — in which case the order is that command's.
    The mock always used the row's own key order, so `eval z=1, a=2` declared
    `z` before `a` where splunkd declares `a` before `z`.
    """

    def names(self, spl: str) -> list[str]:
        from application.splunk.commands.search import describe_fields

        rows, _messages = run(spl)
        return [f["name"] for f in describe_fields(parse_spl(spl), rows)]

    def test_a_plain_search_declares_its_columns_by_name(self) -> None:
        assert self.names('| makeresults format=csv data="b,a\n1,2"') == ["a", "b"]

    def test_eval_does_not_fix_the_order_either(self) -> None:
        assert self.names("| makeresults count=1 | eval z=1, a=2") == ["_time", "a", "z"]

    def test_table_declares_the_order_it_was_given(self) -> None:
        assert self.names('| makeresults format=csv data="b,a\n1,2" | table b, a') == ["b", "a"]

    def test_a_field_added_after_a_table_is_appended(self) -> None:
        spl = '| makeresults format=csv data="b,a\n1,2" | table b, a | eval c=1'
        assert self.names(spl) == ["b", "a", "c"]

    def test_stats_keeps_the_order_it_wrote(self) -> None:
        spl = '| makeresults format=csv data="b,a\n1,2" | stats sum(a) as zz, count as m by b'
        assert self.names(spl) == ["b", "zz", "m"]

    def test_streamstats_does_not_build_the_row(self) -> None:
        spl = '| makeresults format=csv data="b,a\n1,2" | streamstats count'
        assert self.names(spl) == ["a", "b", "count"]

    def test_a_column_only_some_rows_carry_is_still_declared(self) -> None:
        spl = ROWS + "| streamstats current=f sum(n) as s"
        assert self.names(spl) == ["g", "n", "s"]

    def test_stats_declares_a_column_it_could_not_compute(self) -> None:
        # No row carries `sum(g)`; splunkd names it anyway.
        assert self.names(ROWS + "| stats sum(g) by n") == ["n", "sum(g)"]

    def test_streamstats_does_not(self) -> None:
        assert self.names(ROWS + "| streamstats count by nosuchfield") == ["g", "n"]
