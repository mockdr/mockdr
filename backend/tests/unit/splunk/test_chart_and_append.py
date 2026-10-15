"""``chart``, ``append`` and ``join``: the pivot, and the subsearches.

``chart`` is ``stats`` with its second by-field turned into columns (chart
command reference): one row per value of the row field, one column per value
of the column field, the columns past ``limit`` folded into ``OTHER``, and a
row without the column field counted under ``NULL``. ``append`` runs a
subsearch and adds its results after the current ones, at most ``maxout``
(50,000) of them; ``join`` matches each row to the subsearch's rows on the
join fields — inner by default, one match per row unless ``max`` says
otherwise (join command reference). All three were unknown commands here.

Subsearches nest, and a search made of brackets inside brackets must not be
able to recurse without end: mockdr follows four levels and refuses the
fifth, and runs at most sixteen subsearches in one search.
"""
from tests.unit.splunk.sources import FakeSources, failure, out
from utils.splunk.spl_data_cmds import (
    MAX_APPEND_ROWS,
    MAX_APPENDED_TOTAL,
    MAX_SUBSEARCH_DEPTH,
    MAX_SUBSEARCHES,
)

ROWS = ('| makeresults format=csv data="host,action,bytes\n'
        'a,allow,10\na,block,20\nb,allow,30\nb,allow,40\nc,,50" ')
NONE = FakeSources()


class TestChart:
    """A statistics table pivoted on two fields."""

    def test_over_and_by_make_rows_and_columns(self) -> None:
        assert out(ROWS + "| chart count over host by action", NONE) == [
            {"host": "a", "NULL": 0, "allow": 1, "block": 1},
            {"host": "b", "NULL": 0, "allow": 2, "block": 0},
            {"host": "c", "NULL": 1, "allow": 0, "block": 0},
        ]

    def test_by_with_two_fields_means_the_same(self) -> None:
        assert out(ROWS + "| chart count by host, action", NONE) == out(
            ROWS + "| chart count over host by action", NONE)

    def test_usenull_false_drops_the_rows_without_the_column_field(self) -> None:
        rows = out(ROWS + "| chart usenull=f count over host by action", NONE)
        assert "NULL" not in rows[0] and len(rows) == 3

    def test_an_empty_cell_of_a_sum_is_absent(self) -> None:
        rows = out(ROWS + "| chart sum(bytes) over host by action", NONE)
        assert rows[1] == {"host": "b", "allow": 70}

    def test_one_field_is_stats_by_it(self) -> None:
        assert out(ROWS + "| chart count, avg(bytes) by host", NONE) == [
            {"host": "a", "count": 2, "avg(bytes)": 15},
            {"host": "b", "count": 2, "avg(bytes)": 35},
            {"host": "c", "count": 1, "avg(bytes)": 50},
        ]

    def test_no_split_is_one_row(self) -> None:
        assert out(ROWS + "| chart count", NONE) == [{"count": 5}]

    def test_several_statistics_name_their_columns(self) -> None:
        row = out(ROWS + "| chart count, sum(bytes) over host by action", NONE)[0]
        assert row["count: allow"] == 1 and row["sum(bytes): block"] == 20

    def test_columns_past_the_limit_fold_into_other(self) -> None:
        rows = out(ROWS + "| chart limit=1 count over host by action", NONE)
        assert rows == [
            {"host": "a", "allow": 1, "OTHER": 1},
            {"host": "b", "allow": 2, "OTHER": 0},
            {"host": "c", "allow": 0, "OTHER": 1},
        ]

    def test_useother_false_drops_them(self) -> None:
        rows = out(ROWS + "| chart limit=1 useother=f count over host by action", NONE)
        assert rows[0] == {"host": "a", "allow": 1}

    def test_otherstr_renames_the_fold(self) -> None:
        rows = out(ROWS + "| chart limit=1 otherstr=rest count over host by action", NONE)
        assert rows[0] == {"host": "a", "allow": 1, "rest": 1}

    def test_limit_takes_topn(self) -> None:
        assert out(ROWS + "| chart limit=top1 count over action by host", NONE) == out(
            ROWS + "| chart limit=1 count over action by host", NONE)

    def test_a_bad_limit_is_refused(self) -> None:
        assert "limit" in failure(ROWS + "| chart limit=x count by host", NONE)

    def test_a_third_field_is_refused(self) -> None:
        assert "The argument 'bytes' is invalid." in failure(
            ROWS + "| chart count by host, action, bytes", NONE)

    def test_no_statistic_is_refused(self) -> None:
        assert failure(ROWS + "| chart by host", NONE) == (
            "Error in 'chart' command: You must specify data field(s) to chart."
        )

    def test_an_unknown_statistic_is_refused(self) -> None:
        assert "invalid" in failure(ROWS + "| chart nosuch(bytes) by host", NONE)


class TestAppend:
    """A subsearch's results, after the current ones."""

    def test_the_subsearch_rows_follow(self) -> None:
        rows = out('| makeresults | eval n=1 | append [| makeresults count=2 | eval n=2] '
                   "| table n", NONE)
        assert rows == [{"n": 1}, {"n": 2}, {"n": 2}]

    def test_maxout_caps_the_subsearch(self) -> None:
        rows = out("| makeresults | append maxout=1 [| makeresults count=5]", NONE)
        assert len(rows) == 2

    def test_and_the_cap_cannot_be_raised(self) -> None:
        rows = out(f"| makeresults count=0 | append maxout={MAX_APPEND_ROWS * 10} "
                   "[| makeresults count=50000 | append [| makeresults count=50000]]", NONE)
        assert len(rows) == MAX_APPEND_ROWS

    def test_a_subsearch_that_fails_fails_the_search_in_its_own_words(self) -> None:
        assert failure('| makeresults | append [| makeresults | eval x=1==1]', NONE) == (
            "Error in 'EvalCommand': Fields cannot be assigned a boolean result. "
            "Instead, try if([bool expr], [expr], [expr])."
        )

    def test_an_unknown_command_in_the_subsearch_is_refused(self) -> None:
        assert "Unknown search command 'nosuch'" in failure(
            "| makeresults | append [| nosuch]", NONE)

    def test_a_missing_subsearch_is_refused(self) -> None:
        assert failure("| makeresults | append maxout=3", NONE) == (
            "Error in 'append' command: Missing subsearch."
        )

    def test_an_unknown_option_is_refused(self) -> None:
        assert "Invalid argument: 'nosuch=1'" in failure(
            "| makeresults | append nosuch=1 [| makeresults]", NONE)

    def test_subsearches_nest(self) -> None:
        nested = "| makeresults"
        for _ in range(MAX_SUBSEARCH_DEPTH):
            nested = f"| makeresults | append [{nested}]"
        assert len(out(nested, NONE)) == MAX_SUBSEARCH_DEPTH + 1

    def test_but_not_without_end(self) -> None:
        nested = "| makeresults"
        for _ in range(MAX_SUBSEARCH_DEPTH + 1):
            nested = f"| makeresults | append [{nested}]"
        assert "nested at most" in failure(nested, NONE)

    def test_a_flat_chain_of_subsearches_is_bounded_too(self) -> None:
        chain = "| makeresults" + " | append [| makeresults]" * (MAX_SUBSEARCHES + 1)
        assert "at most" in failure(chain, NONE)
        within = "| makeresults" + " | append [| makeresults]" * MAX_SUBSEARCHES
        assert len(out(within, NONE)) == MAX_SUBSEARCHES + 1

    def test_appends_cannot_grow_the_rows_without_end(self) -> None:
        chain = "| makeresults count=50000" + " | append [| makeresults count=50000]" * 3
        assert len(out(chain, NONE)) == MAX_APPENDED_TOTAL

    def test_a_subsearch_reads_the_same_sources(self) -> None:
        sources = FakeSources(events=[{"_time": 1.0, "index": "main", "host": "h"}])
        rows = out("| makeresults | append [search index=main | table host]", sources)
        assert rows[1] == {"host": "h"}


#: Three hosts on the left; owners for two of them, one twice, on the right.
LEFT = '| makeresults format=csv data="host,n\na,1\nb,2\nc,3" '
RIGHT = '[| makeresults format=csv data="host,owner\na,alice\nb,bob\nb,bert"]'


class TestJoin:
    """A row joined to the subsearch rows that agree on the join fields."""

    def test_an_inner_join_drops_the_rows_that_match_nothing(self) -> None:
        assert out(LEFT + "| join host " + RIGHT, NONE) == [
            {"host": "a", "n": "1", "owner": "alice"},
            {"host": "b", "n": "2", "owner": "bob"},
        ]

    def test_a_left_join_keeps_them(self) -> None:
        rows = out(LEFT + "| join type=left host " + RIGHT, NONE)
        assert rows[2] == {"host": "c", "n": "3"}

    def test_outer_means_left(self) -> None:
        assert out(LEFT + "| join type=outer host " + RIGHT, NONE) == out(
            LEFT + "| join type=left host " + RIGHT, NONE)

    def test_max_zero_takes_every_match(self) -> None:
        rows = out(LEFT + "| join max=0 host " + RIGHT, NONE)
        assert [r["owner"] for r in rows] == ["alice", "bob", "bert"]

    def test_without_fields_the_shared_ones_join(self) -> None:
        assert out(LEFT + "| join " + RIGHT, NONE) == out(LEFT + "| join host " + RIGHT, NONE)

    def test_the_subsearch_wins_unless_overwrite_is_off(self) -> None:
        right = '[| makeresults format=csv data="host,n\na,99"]'
        assert out(LEFT + "| join host " + right, NONE)[0]["n"] == "99"
        assert out(LEFT + "| join overwrite=f host " + right, NONE)[0]["n"] == "1"

    def test_usetime_joins_only_earlier_rows(self) -> None:
        sub = ('[| makeresults count=2 | streamstats count '
               '| eval host="a", _time=if(count==1, 50, 150), v=count]')
        main = '| makeresults | eval host="a", _time=100 '
        assert out(main + "| join usetime=t host " + sub, NONE)[0]["v"] == 1
        assert out(main + "| join usetime=t earlier=f host " + sub, NONE)[0]["v"] == 2

    def test_an_unknown_type_is_refused(self) -> None:
        assert "type" in failure(LEFT + "| join type=cross host " + RIGHT, NONE)

    def test_an_unknown_option_is_refused(self) -> None:
        assert "Invalid argument: 'nosuch=1'" in failure(
            LEFT + "| join nosuch=1 host " + RIGHT, NONE)

    def test_a_join_needs_its_subsearch(self) -> None:
        assert failure(LEFT + "| join host", NONE) == (
            "Error in 'join' command: Missing subsearch."
        )
