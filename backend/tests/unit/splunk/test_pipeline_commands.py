"""The commands SOAR content uses that mockdr refused, measured against 10.4.2.

`eventstats`, `mvexpand`, `filldown`, `spath`, `convert` and `bin` were all
unknown commands here, so a search using any of them was refused outright —
and `| table *` selected a field literally named ``*`` and returned nothing.
62 searches were run against a real instance and this one and compared.

Two differences are left in place deliberately, both measured and both
splunkd's own bookkeeping about *declared* fields rather than about values:

* `convert num(text_field) as m | table m` gives one empty row per event
  there and no rows here. splunkd's `table` keeps a row when a command
  declared the field, even though no row carries a value for it; mockdr has
  no schema to declare into.
* `spath` over a document whose field the row already carries writes a
  two-value multivalue there when the two values differ only in type
  (`true` the boolean against `"true"` the text), and one value here.
"""
import pytest

from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl

ROWS = '| makeresults format=csv data="n,g\n1,a\n2,b\n3,a\n4,b" '
DOC = (
    '| makeresults format=json data="[{\\"a\\":{\\"b\\":1},\\"c\\":[1,2],'
    '\\"d\\":[{\\"e\\":1},{\\"e\\":2}],\\"f\\":null}]" '
)


def out(spl: str, rows: list[dict] | None = None) -> list[dict]:
    """The rows a pipeline produces, failing loudly if it did not run."""
    produced, messages = execute_pipeline(list(rows or []), parse_spl(spl))
    fatal = [m for m in messages if m["type"] == "FATAL"]
    if fatal:
        pytest.fail(f"unexpected failure: {fatal[0]['text']}")
    return produced


def failure(spl: str) -> str:
    """The FATAL text a pipeline produces."""
    _rows, messages = execute_pipeline([], parse_spl(spl))
    assert messages, "expected the search to fail"
    return messages[0]["text"]


class TestEventstats:
    """stats over the whole set, joined onto every row."""

    def test_the_count_is_the_same_on_every_row(self) -> None:
        assert [r["count"] for r in out(ROWS + "| eventstats count")] == [4, 4, 4, 4]

    def test_a_grouping_gives_each_row_its_own_group(self) -> None:
        assert [r["a"] for r in out(ROWS + "| eventstats avg(n) as a by g")] == [2, 3, 2, 3]

    def test_the_row_keeps_its_own_fields(self) -> None:
        assert out(ROWS + "| eventstats count")[0] == {"n": "1", "g": "a", "count": 4}

    def test_an_aggregation_with_nothing_to_compute_writes_no_field(self) -> None:
        assert out(ROWS + "| eventstats sum(g) as s")[0] == {"n": "1", "g": "a"}

    def test_a_row_without_the_by_field_is_left_alone(self) -> None:
        assert out(ROWS + "| eventstats count by nosuchfield")[0] == {"n": "1", "g": "a"}

    def test_it_takes_allnum_and_limit(self) -> None:
        assert out(ROWS + "| eventstats allnum=t count limit=2")[0]["count"] == 4

    def test_and_refuses_anything_else(self) -> None:
        assert failure(ROWS + "| eventstats count nosucharg=1") == (
            "Error in 'eventstats' command: The argument 'nosucharg=1' is invalid."
        )


class TestMvexpand:
    """One row per value of a multivalue field."""

    def test_each_value_becomes_a_row(self) -> None:
        rows = out(ROWS + '| eval m=split("x;y",";") | mvexpand m | table n, m')
        assert rows[:2] == [{"n": "1", "m": "x"}, {"n": "1", "m": "y"}]
        assert len(rows) == 8

    def test_a_limit_caps_the_values_taken_from_each_row(self) -> None:
        rows = out(ROWS + '| eval m=split("x;y",";") | mvexpand m limit=1 | table n, m')
        assert [r["m"] for r in rows] == ["x", "x", "x", "x"]

    def test_a_limit_of_zero_is_no_limit(self) -> None:
        rows = out(ROWS + '| eval m=split("x;y",";") | mvexpand m limit=0')
        assert len(rows) == 8

    def test_a_single_value_passes_through(self) -> None:
        assert len(out(ROWS + "| mvexpand n")) == 4

    def test_a_field_the_rows_lack_leaves_them_alone(self) -> None:
        assert out(ROWS + "| mvexpand nosuchfield")[0] == {"n": "1", "g": "a"}

    def test_only_one_field_at_a_time(self) -> None:
        assert failure(ROWS + "| mvexpand n, g") == (
            "Error in 'mvexpand' command: Invalid argument: 'g'"
        )

    def test_a_field_is_required(self) -> None:
        assert failure(ROWS + "| mvexpand") == (
            "Error in 'mvexpand' command: A field name is expected."
        )

    def test_the_limit_is_checked_by_the_search_processor(self) -> None:
        # Not by the command — a different subject in the message.
        assert failure(ROWS + '| eval m=split("x;y",";") | mvexpand m limit=-1') == (
            "Error in 'SearchProcessor': Invalid option value. Expecting a "
            "'non-negative integer' for option 'limit'. Instead got '-1'."
        )


class TestFilldown:
    """Carrying the last value a field had into the rows that lack it."""

    def test_the_named_field_is_carried_down(self) -> None:
        rows = out(ROWS + '| eval x=if(n=2,"v",null()) | filldown x | table n, x')
        assert [r.get("x") for r in rows] == [None, "v", "v", "v"]

    def test_without_a_field_it_carries_them_all(self) -> None:
        rows = out(ROWS + '| eval x=if(n=2,"v",null()) | filldown | table n, x')
        assert [r.get("x") for r in rows] == [None, "v", "v", "v"]

    def test_a_field_no_row_has_changes_nothing(self) -> None:
        assert out(ROWS + "| filldown nosuchfield")[0] == {"n": "1", "g": "a"}


class TestSpath:
    """Reading JSON out of a field into fields of its own."""

    def test_every_path_becomes_a_field(self) -> None:
        row = out(DOC + "| spath")[0]
        assert row["a.b"] == "1"
        assert row["c{}"] == ["1", "2"]
        assert row["d{}.e"] == ["1", "2"]

    def test_a_container_is_written_as_its_own_json(self) -> None:
        row = out(DOC + "| spath")[0]
        assert row["a"] == '{"b":1}'
        assert row["c"] == "[1,2]"

    def test_a_path_selects_one(self) -> None:
        assert out(DOC + "| spath path=a.b")[0]["a.b"] == "1"

    def test_output_names_where_it_goes(self) -> None:
        assert out(DOC + "| spath output=z path=d{}.e")[0]["z"] == ["1", "2"]

    def test_a_path_that_is_not_there_writes_nothing(self) -> None:
        assert "nosuch" not in out(DOC + "| spath path=nosuch")[0]

    def test_a_field_that_is_not_json_leaves_the_row_alone(self) -> None:
        rows = out('| makeresults | eval j="not json" | spath input=j')
        assert "a" not in rows[0]

    def test_input_names_the_field_to_read(self) -> None:
        rows = out(r'| makeresults | eval j="{\"k\":7}" | spath input=j')
        assert rows[0]["k"] == "7"


class TestConvert:
    """Converting field values between the shapes splunkd knows."""

    def test_num_takes_the_number(self) -> None:
        assert [r["m"] for r in out(ROWS + "| convert num(n) as m")] == [1, 2, 3, 4]

    def test_a_conversion_that_does_not_apply_writes_nothing(self) -> None:
        assert "m" not in out(ROWS + "| convert num(g) as m")[0]

    def test_without_an_alias_it_converts_in_place(self) -> None:
        assert out(ROWS + "| convert num(n)")[0]["n"] == 1

    def test_a_wildcard_converts_every_field(self) -> None:
        # And drops the ones it could not convert.
        row = out(ROWS + "| convert num(*)")[0]
        assert row == {"n": 1}

    def test_ctime_renders_an_epoch(self) -> None:
        assert out(ROWS + "| convert ctime(n) as t")[0]["t"] == "01/01/1970 00:00:01"

    def test_timeformat_chooses_how(self) -> None:
        rows = out(ROWS + '| convert timeformat="%Y" ctime(n) as t')
        assert rows[0]["t"] == "1970"

    def test_dur2sec_reads_a_duration(self) -> None:
        rows = out('| makeresults | eval d="00:10:15" | convert dur2sec(d) as s')
        assert rows[0]["s"] == 615

    def test_rmunit_drops_the_unit(self) -> None:
        rows = out('| makeresults | eval d="15ms" | convert rmunit(d) as s')
        assert rows[0]["s"] == 15

    def test_rmcomma_drops_the_separators(self) -> None:
        rows = out('| makeresults | eval d="1,234,567" | convert rmcomma(d) as s')
        assert rows[0]["s"] == 1234567

    def test_none_hands_the_value_back(self) -> None:
        assert out(ROWS + "| convert none(g) as m")[0]["m"] == "a"

    def test_a_type_it_does_not_have_is_refused(self) -> None:
        assert failure(ROWS + "| convert nosuchfunc(n)") == (
            "Error in 'convert' command: The conversion type 'nosuchfunc' is invalid."
        )


class TestBin:
    """Grouping a field's values into buckets."""

    def test_a_numeric_span_writes_the_range(self) -> None:
        assert [r["n"] for r in out(ROWS + "| bin n span=2")] == [
            "0-2", "2-4", "2-4", "4-6",
        ]

    def test_the_span_decides_how_the_edges_are_written(self) -> None:
        assert out(ROWS + "| bin n span=0.5")[0]["n"] == "1.0-1.5"

    def test_the_default_span_is_one(self) -> None:
        assert [r["n"] for r in out(ROWS + "| bin n")] == ["1-2", "2-3", "3-4", "4-5"]

    def test_bucket_is_the_same_command(self) -> None:
        assert out(ROWS + "| bucket n span=2")[0]["n"] == "0-2"

    def test_bins_rounds_the_span_up_to_a_power_of_ten(self) -> None:
        # Four values across a range of 3 in two bins is one bucket of 10.
        assert [r["n"] for r in out(ROWS + "| bin n bins=2")] == ["0-10"] * 4

    def test_minspan_does_the_same(self) -> None:
        assert out(ROWS + "| bin n minspan=3")[0]["n"] == "0-10"

    def test_as_names_the_bucket_and_keeps_the_field(self) -> None:
        row = out(ROWS + "| bin n span=2 as z")[0]
        assert row["z"] == "0-2"
        assert row["n"] == "1"

    def test_a_time_span_writes_the_bucket_start_alone(self) -> None:
        events = [{"_time": 1787500000.0 + 3600 * i} for i in range(5)]
        rows = out("search * | bin _time span=2h", events)
        # Which is what makes `| bin _time span=2h | stats count by _time` an
        # hourly count: the value is the bucket, not a range.
        assert [r["_time"] for r in rows] == [
            1787493600, 1787500800, 1787500800, 1787508000, 1787508000,
        ]

    def test_a_row_without_the_field_is_left_alone(self) -> None:
        assert out(ROWS + "| bin nosuchfield span=2")[0] == {"n": "1", "g": "a"}

    def test_a_field_is_required(self) -> None:
        assert failure(ROWS + "| bin") == (
            "Error in 'bin' command: You must specify a field to discretize."
        )

    def test_an_argument_it_cannot_read_is_refused(self) -> None:
        assert failure(ROWS + "| bin n nosucharg=1") == (
            "Error in 'bin' command: Invalid argument: 'nosucharg=1'"
        )


class TestWildcardFieldSelection:
    """`table *` and `fields host*`, which selected a field named `*`."""

    def test_table_star_keeps_every_field(self) -> None:
        assert out(ROWS + "| table *")[0] == {"n": "1", "g": "a"}

    def test_a_prefix_selects_what_it_matches(self) -> None:
        assert out(ROWS + "| table n*")[0] == {"n": "1"}

    def test_fields_reads_the_same_patterns(self) -> None:
        assert out(ROWS + "| fields *")[0] == {"n": "1", "g": "a"}

    def test_a_pattern_that_matches_nothing_still_selects_nothing(self) -> None:
        assert out(ROWS + "| table zz*") == []
