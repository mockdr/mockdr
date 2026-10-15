"""What the ``fields`` block says about the columns tstats and chart make.

Measured on splunkd 10.4.2 via the conformance stack, over the seeded
conformance events:

- ``tstats … by host`` (and by two fields, and by ``_time span=2h``) lists
  its columns with no ``groupby_rank`` at all — ``stats`` ranks the same
  columns, and mockdr ranked tstats' as well;
- ``chart … over host by action`` ranks the row field and describes each
  split column: ``data_source`` (the statistic's alias), ``splitby_field``,
  ``splitby_value``, and ``splitby_special`` ``other``/``null`` for OTHER
  and NULL — with several statistics the column ``count: allow`` is
  ``data_source: count``, ``splitby_value: allow``;
- NULL comes last, after OTHER, and is never folded into OTHER; a row
  without the row field makes no column;
- the description follows a column through ``rename`` (a stats group-by
  rank too) and survives fields, eval, sort, where and head; a ``table``
  afterwards drops all of it.
"""
from __future__ import annotations

from application.splunk.commands.search import describe_fields
from tests.unit.splunk.sources import FakeSources, run
from utils.splunk.spl_parser import parse_spl

EVENTS = [
    {"_time": 1787752800 + 3600 * i, "index": "main", "host": host, "action": action,
     "user": user, "sourcetype": "probe"}
    for i, (host, action, user) in enumerate([
        ("srv-1", "allow", "alice"), ("srv-1", "block", "bob"), ("srv-2", "allow", "alice"),
        ("srv-2", "block", "carol"), ("srv-3", "allow", "alice"),
    ])
]
SOURCES = FakeSources(events=EVENTS)


def fields(spl: str) -> list[dict]:
    rows, messages = run(spl, SOURCES, rows=[dict(e) for e in EVENTS])
    assert not [m for m in messages if m["type"] == "FATAL"], messages
    return describe_fields(parse_spl(spl), rows)


def split(name: str, value: str, field: str = "action", source: str = "count",
          special: str = "") -> dict:
    entry = {"name": name, "data_source": source, "splitby_field": field,
             "splitby_value": value}
    if special:
        entry["splitby_special"] = special
    return entry


class TestTstats:
    def test_by_one_field_carries_no_rank(self) -> None:
        assert fields("| tstats count where index=main by host") == [
            {"name": "host"}, {"name": "count"}]

    def test_by_two_fields_neither(self) -> None:
        assert fields("| tstats count where index=main by host sourcetype") == [
            {"name": "host"}, {"name": "sourcetype"}, {"name": "count"}]

    def test_by_a_time_span_neither(self) -> None:
        assert fields("| tstats count where index=main by _time span=2h") == [
            {"name": "_time"}, {"name": "count"}]

    def test_a_stats_after_it_ranks_its_own(self) -> None:
        assert fields("| tstats count where index=main by host "
                      "| stats sum(count) by host")[0] == {"groupby_rank": "0", "name": "host"}


class TestChart:
    def test_split_columns_say_what_they_hold(self) -> None:
        assert fields("search * | chart count over host by action") == [
            {"name": "host", "groupby_rank": "0"},
            split("allow", "allow"), split("block", "block"),
        ]

    def test_by_two_fields_is_the_same(self) -> None:
        assert fields("search * | chart count by host action") == fields(
            "search * | chart count over host by action")

    def test_an_alias_is_the_data_source(self) -> None:
        assert fields("search * | chart dc(user) as n over host by action")[1] == split(
            "allow", "allow", source="n")

    def test_several_statistics_name_theirs(self) -> None:
        described = fields("search * | chart count dc(user) over host by action")
        assert split("count: allow", "allow") in described
        assert split("dc(user): block", "block", source="dc(user)") in described

    def test_other_is_special(self) -> None:
        assert fields("search * | chart limit=1 count over action by user") == [
            {"name": "action", "groupby_rank": "0"},
            split("alice", "alice", field="user"),
            split("OTHER", "OTHER", field="user", special="other"),
        ]

    def test_null_comes_last_and_is_never_folded(self) -> None:
        spl = ('search * | eval grp=if(host=="srv-3", null(), action) '
               "| chart limit=1 count over host by grp")
        assert fields(spl) == [
            {"name": "host", "groupby_rank": "0"},
            split("allow", "allow", field="grp"),
            split("OTHER", "OTHER", field="grp", special="other"),
            split("NULL", "NULL", field="grp", special="null"),
        ]
        rows, _ = run(spl, SOURCES, rows=[dict(e) for e in EVENTS])
        assert rows[2] == {"host": "srv-3", "allow": 0, "OTHER": 0, "NULL": 1}

    def test_a_row_without_the_row_field_makes_no_column(self) -> None:
        spl = ('search * | eval grp=if(host=="srv-3", null(), action) '
               "| chart count over grp by host")
        assert [f["name"] for f in fields(spl)] == ["grp", "srv-1", "srv-2"]

    def test_the_description_follows_a_rename(self) -> None:
        described = fields("search * | chart count over host by action | rename allow as A")
        assert described[1] == {**split("allow", "allow"), "name": "A"}

    def test_it_survives_eval_sort_where_head_and_fields(self) -> None:
        for tail in ("| eval z=1", "| sort - host", "| where allow>0", "| head 1",
                     "| fields host allow"):
            described = fields(f"search * | chart count over host by action {tail}")
            assert described[1] == split("allow", "allow"), tail

    def test_a_table_drops_it(self) -> None:
        assert fields("search * | chart count over host by action | table host allow") == [
            {"name": "host"}, {"name": "allow"}]


class TestStatsRankThroughRenameAndTable:
    def test_rename_carries_the_rank(self) -> None:
        assert fields("search * | stats count by host | rename host as h")[0] == {
            "name": "h", "groupby_rank": "0"}

    def test_table_drops_it(self) -> None:
        assert fields("search * | stats count by host | table host count") == [
            {"name": "host"}, {"name": "count"}]
