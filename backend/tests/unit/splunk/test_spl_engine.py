"""SPL engine semantics.

The previous engine flattened the pipeline into fixed-order flags, kept only
the first ``where`` clause, treated every operator as equality, and silently
dropped any command it did not recognise — so a query asking for ``| stats
count`` came back as the full unfiltered event set with no diagnostic.
"""
import pytest

from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl

ROWS = [
    {"_time": "300", "host": "alpha", "sourcetype": "web", "code": 200, "bytes": 10},
    {"_time": "100", "host": "beta", "sourcetype": "web", "code": 404, "bytes": 20},
    {"_time": "200", "host": "alpha", "sourcetype": "db", "code": 500, "bytes": 30},
]


def run(spl: str, rows: list[dict] | None = None) -> tuple[list[dict], list[str]]:
    """Parse and execute *spl*, returning rows and diagnostics."""
    query = parse_spl(spl)
    return execute_pipeline(list(rows if rows is not None else ROWS), query)


class TestPipelineOrder:
    """Commands run in the order written."""

    def test_head_before_sort_differs_from_sort_before_head(self) -> None:
        head_first, _ = run("search * | head 1 | sort bytes")
        sort_first, _ = run("search * | sort -bytes | head 1")

        assert head_first[0]["host"] == "alpha"   # first row, then sorted
        assert sort_first[0]["bytes"] == 30       # sorted, then first taken

    def test_filter_after_projection_sees_projected_fields(self) -> None:
        rows, _ = run("search * | table host bytes | where bytes > 15")
        assert len(rows) == 2

    def test_repeated_commands_all_apply(self) -> None:
        rows, _ = run("search * | where bytes > 5 | where bytes < 25")
        assert [r["bytes"] for r in rows] == [10, 20]


class TestWhereOperators:
    """``where`` performs real comparisons, not equality on everything."""

    @pytest.mark.parametrize(
        ("expr", "expected"),
        [
            ("bytes > 15", 2),
            ("bytes >= 20", 2),
            ("bytes < 15", 1),
            ("bytes = 20", 1),
            ("bytes != 20", 2),
            ("code = 404 OR code = 500", 2),
            ("code = 404 AND host = \"beta\"", 1),
            ("NOT code = 404", 2),
        ],
    )
    def test_operator(self, expr: str, expected: int) -> None:
        rows, _ = run(f"search * | where {expr}")
        assert len(rows) == expected

    def test_comparison_against_a_missing_field_is_false(self) -> None:
        # Falling through to string comparison made this true, because
        # "None" sorts after "9".
        rows, _ = run("search * | where nosuchfield > 900000")
        assert rows == []


class TestSearchClause:
    """Wildcards, NOT and OR in the search clause."""

    def test_wildcard_matches(self) -> None:
        rows, _ = run("search host=alph*")
        assert len(rows) == 2

    def test_not_excludes(self) -> None:
        rows, _ = run("search NOT sourcetype=db")
        assert len(rows) == 2

    def test_not_on_a_builtin_selector_is_not_hoisted(self) -> None:
        # `NOT sourcetype=x` was lifted into `sourcetype == x`, inverting the
        # query into its own opposite.
        query = parse_spl("search index=main NOT sourcetype=db")
        assert query.sourcetype != "db"

    def test_or_between_terms(self) -> None:
        rows, _ = run("search sourcetype=db OR host=beta")
        assert len(rows) == 2

    def test_free_text_matches_event_content(self) -> None:
        assert len(run("search alpha")[0]) == 2
        assert run("search definitely_not_present")[0] == []


class TestStats:
    """``stats`` aggregates instead of passing rows through."""

    def test_count_collapses_to_one_row(self) -> None:
        rows, _ = run("search * | stats count")
        assert rows == [{"count": 3}]

    def test_count_by_groups(self) -> None:
        rows, _ = run("search * | stats count by sourcetype")
        assert {r["sourcetype"]: r["count"] for r in rows} == {"web": 2, "db": 1}

    @pytest.mark.parametrize(
        ("func", "expected"),
        [("sum(bytes)", 60), ("avg(bytes)", 20), ("min(bytes)", 10),
         ("max(bytes)", 30), ("dc(host)", 2)],
    )
    def test_functions(self, func: str, expected: object) -> None:
        rows, _ = run(f"search * | stats {func}")
        assert rows[0][func] == expected

    def test_alias(self) -> None:
        rows, _ = run("search * | stats sum(bytes) as total")
        assert rows[0]["total"] == 60


class TestOtherCommands:
    """The commands a real SPL user reaches for."""

    def test_dedup(self) -> None:
        rows, _ = run("search * | dedup sourcetype")
        assert len(rows) == 2

    def test_top(self) -> None:
        rows, _ = run("search * | top host")
        assert rows[0]["host"] == "alpha"
        assert rows[0]["count"] == 2

    def test_fields_projection(self) -> None:
        rows, _ = run("search * | fields host")
        assert all(set(r) == {"host"} for r in rows)

    def test_fields_removal(self) -> None:
        rows, _ = run("search * | fields - host")
        assert all("host" not in r for r in rows)

    def test_rename(self) -> None:
        rows, _ = run("search * | rename host as machine")
        assert "machine" in rows[0]
        assert "host" not in rows[0]

    def test_rex_extracts_named_groups(self) -> None:
        rows, _ = run(
            'search * | rex field=host "(?<prefix>al)"',
            [{"host": "alpha"}],
        )
        assert rows[0]["prefix"] == "al"

    def test_regex_filters(self) -> None:
        rows, _ = run('search * | regex host="^al"')
        assert len(rows) == 2


class TestEval:
    """``eval`` computes a value rather than storing its own source text."""

    def test_arithmetic(self) -> None:
        rows, _ = run("search * | eval doubled=bytes*2")
        assert [r["doubled"] for r in rows] == [20, 40, 60]

    def test_if_selects_a_branch(self) -> None:
        rows, _ = run('search * | eval sev=if(code>=500,"high","low")')
        assert [r["sev"] for r in rows] == ["low", "low", "high"]

    def test_string_concat(self) -> None:
        rows, _ = run('search * | eval label=host.":".sourcetype')
        assert rows[0]["label"] == "alpha:web"

    def test_functions(self) -> None:
        rows, _ = run("search * | eval up=upper(host)")
        assert rows[0]["up"] == "ALPHA"

    def test_multiple_assignments(self) -> None:
        rows, _ = run("search * | eval a=1, b=2")
        assert rows[0]["a"] == 1
        assert rows[0]["b"] == 2


class TestSort:
    """Sorting is numeric where it can be, and honours several keys."""

    def test_numeric_not_lexicographic(self) -> None:
        rows, _ = run("search * | sort code", [
            {"code": 20}, {"code": 128}, {"code": 120},
        ])
        assert [r["code"] for r in rows] == [20, 120, 128]

    def test_descending(self) -> None:
        rows, _ = run("search * | sort -bytes")
        assert [r["bytes"] for r in rows] == [30, 20, 10]

    def test_multiple_keys(self) -> None:
        rows, _ = run("search * | sort sourcetype, -bytes")
        assert [(r["sourcetype"], r["bytes"]) for r in rows] == [
            ("db", 30), ("web", 20), ("web", 10),
        ]


class TestUnknownCommandsAreReported:
    """A command the engine cannot run must not look like a successful search."""

    def test_unknown_command_produces_a_message(self) -> None:
        _, messages = run("search * | boguscommand foo")
        # splunkd refuses the dispatch outright, so it is FATAL and the
        # pipeline stops there rather than running what it recognised.
        assert messages == [{
            "type": "FATAL", "text": "Unknown search command 'boguscommand'.",
        }]

    def test_known_commands_produce_no_messages(self) -> None:
        _, messages = run("search * | stats count")
        assert messages == []
