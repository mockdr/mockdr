"""``drop_dm_object_name``, and the wildcard ``rename`` it expands to.

Nearly every Enterprise Security correlation search ends its ``tstats``
with `` `drop_dm_object_name(Processes)` ``, the CIM add-on's macro for
``rename Processes.* AS *``: the dataset prefix comes off and the fields
read as the CIM names. mockdr expanded only `notable`, so the macro reached
the parser as a command called `` `drop_dm_object_name(processes)` `` — and
``rename`` read ``*`` as a literal character, so expanding it would not have
helped either.

A wildcard in ``rename`` matches any run of characters, and each ``*`` in the
new name takes what the matching one in the old name matched (rename
command reference). Expansion is a single pass, so a definition is never
expanded again.
"""
from tests.unit.splunk.sources import FakeSources, out
from utils.splunk.spl_macros import MACROS, expand_macros
from utils.splunk.spl_parser import parse_spl

ROWS = ('| makeresults format=csv data="Processes.dest,Processes.user,count\n'
        'wks-1,alice,3" ')
NONE = FakeSources()


class TestWildcardRename:
    """``*`` in a field name."""

    def test_a_prefix_comes_off(self) -> None:
        assert out(ROWS + "| rename Processes.* AS *", NONE) == [
            {"dest": "wks-1", "user": "alice", "count": "3"},
        ]

    def test_the_star_carries_into_the_new_name(self) -> None:
        rows = out(ROWS + "| rename Processes.* AS p_*", NONE)
        assert set(rows[0]) == {"p_dest", "p_user", "count"}

    def test_a_star_in_the_middle(self) -> None:
        rows = out('| makeresults format=csv data="a_x_1,a_y_1\n1,2" | rename a_*_1 AS b_*',
                   NONE)
        assert rows == [{"b_x": "1", "b_y": "2"}]

    def test_a_field_the_pattern_does_not_match_keeps_its_name(self) -> None:
        assert "count" in out(ROWS + "| rename Processes.* AS *", NONE)[0]

    def test_an_exact_name_still_wins(self) -> None:
        rows = out(ROWS + "| rename Processes.dest AS host, Processes.* AS *", NONE)
        assert rows == [{"host": "wks-1", "user": "alice", "count": "3"}]

    def test_regex_characters_in_the_name_are_literal(self) -> None:
        rows = out('| makeresults format=csv data="a.b,axb\n1,2" | rename a.* AS z*', NONE)
        assert rows == [{"zb": "1", "axb": "2"}]


class TestDropDmObjectName:
    """The CIM macro expands before the search is parsed."""

    def test_it_strips_the_dataset_prefix(self) -> None:
        assert out(ROWS + "| `drop_dm_object_name(Processes)`", NONE) == out(
            ROWS + "| rename Processes.* AS *", NONE)

    def test_it_is_listed_with_its_argument(self) -> None:
        macro = MACROS["drop_dm_object_name(1)"]
        assert (macro.definition, macro.args, macro.app) == (
            "rename $object$.* AS *", ("object",), "Splunk_SA_CIM")

    def test_the_wrong_arity_is_not_this_macro(self) -> None:
        assert expand_macros("`drop_dm_object_name(a, b)`") == "`drop_dm_object_name(a, b)`"

    def test_a_macro_it_does_not_know_is_left_as_written(self) -> None:
        assert parse_spl("| makeresults | `nosuch`").unknown_command == "`nosuch`"

    def test_notable_still_marks_the_search(self) -> None:
        assert parse_spl("`notable` | head 1").is_notable

    def test_expansion_is_one_pass(self) -> None:
        text = "`drop_dm_object_name(`drop_dm_object_name(X)`)`"
        assert expand_macros(text).count("rename") <= 1
