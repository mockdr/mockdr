"""SPL semantics, measured against Splunk 9 with the same events on both sides.

Five events were sent to a real instance's HEC and to this mock's, then 65
searches run against both and the rows compared. What follows is every
difference that turned out to be a defect here rather than an artifact of the
real instance's bucket ordering or its lazy field extraction.

Two differences are left in place deliberately, both measured:

* splunkd extracts a field only when the search refers to it, so a raw event
  row carries ``_raw``, ``_time``, ``host`` and ``sourcetype`` and little
  else. What it extracts depends on the sourcetype's ``KV_MODE`` and
  ``INDEXED_EXTRACTIONS`` — configuration this mock does not model, so
  imitating one instance's answer would encode that instance's setup.
* ``first()`` and ``last()`` read pipeline order, and the order splunkd
  returns raw events in is a property of how they landed in buckets rather
  than anything it documents.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_expr import evaluate, parse_search
from utils.splunk.spl_parser import parse_spl

ROWS = [
    {"_time": 1787500000.0, "host": "srv-1", "sev": 10, "action": "allow", "user": "alice"},
    {"_time": 1787503600.0, "host": "srv-1", "sev": 20, "action": "block", "user": "bob"},
    {"_time": 1787507200.0, "host": "srv-2", "sev": 30, "action": "allow", "user": "alice"},
    {"_time": 1787510800.0, "host": "srv-2", "sev": 40, "action": "block", "user": "carol"},
    {"_time": 1787514400.0, "host": "srv-3", "sev": 50, "action": "allow", "user": "alice"},
]


def run(spl: str, rows: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    """Run a pipeline over the fixture rows."""
    return execute_pipeline(list(ROWS if rows is None else rows), parse_spl(spl))


def rows_of(spl: str, rows: list[dict] | None = None) -> list[dict]:
    """Just the rows a pipeline produces."""
    return run(spl, rows)[0]


class TestParenthesisedSearches:
    """A group in the search clause is a group, not a function call."""

    @pytest.mark.parametrize("clause", [
        "(host=srv-1 OR host=srv-2)",
        "(host=srv-1)",
        "NOT (action=allow)",
        "(action=allow AND sev>25)",
        "((action=allow))",
        "sourcetype=probe:run (action=allow OR sev>35)",
    ])
    def test_a_group_does_not_read_as_a_call(self, clause: str) -> None:
        # `index=main (host=a OR host=b)` used to parse `main(...)` as a
        # function call and raise "unknown function 'main'" out of the
        # handler as a 500 — on one of the most ordinary searches there is.
        node = parse_search(clause)
        assert all(evaluate(node, row, mode="search") in (True, False) for row in ROWS)

    def test_the_group_actually_selects(self) -> None:
        node = parse_search("(host=srv-1 OR host=srv-2)")
        assert sum(1 for r in ROWS if evaluate(node, r, mode="search")) == 4


class TestPipelineFailures:
    """A command that cannot run is FATAL, and takes the result set with it."""

    def test_an_unknown_eval_function_is_fatal(self) -> None:
        rows, messages = run("search * | eval x=nosuchfunc(1)")
        assert rows == []
        assert messages == [{
            "type": "FATAL",
            "text": "Error in 'EvalCommand': The 'nosuchfunc' function is "
                    "unsupported or undefined.",
        }]

    def test_where_names_itself_differently(self) -> None:
        # splunkd reports eval as `EvalCommand` and where as `'where' command`.
        _rows, messages = run("search * | where nosuchfunc(1)")
        assert messages[0]["text"].startswith("Error in 'where' command:")

    def test_a_malformed_expression_quotes_what_it_stopped_on(self) -> None:
        _rows, messages = run("search * | where )(")
        assert messages[0]["type"] == "FATAL"
        assert "The expression is malformed. An unexpected character" in messages[0]["text"]

    def test_an_unknown_command_stops_the_pipeline(self) -> None:
        rows, messages = run("search * | boguscommand foo")
        assert rows == []
        assert messages == [{
            "type": "FATAL", "text": "Unknown search command 'boguscommand'.",
        }]

    def test_the_dispatch_refuses_an_unknown_command(self, splunk_client: TestClient) -> None:
        response = splunk_client.post(
            "/splunk/services/search/jobs",
            headers=splunk_auth(),
            data={"search": "search index=main | boguscommand", "output_mode": "json",
                  "exec_mode": "oneshot"},
        )
        assert response.status_code == 400
        assert response.json()["messages"] == [{
            "type": "FATAL", "text": "Unknown search command 'boguscommand'.",
        }]


class TestOrderingCommands:
    """`head`, `tail` and the sort that feeds them."""

    def test_tail_returns_the_last_rows_in_reverse(self) -> None:
        # `| sort sev | tail 2` answers 50 then 40 on splunkd. Returning them
        # in pipeline order made the first row the smallest.
        assert [r["sev"] for r in rows_of("search * | sort sev | tail 2")] == [50, 40]

    def test_head_returns_the_first_rows_in_order(self) -> None:
        assert [r["sev"] for r in rows_of("search * | sort sev | head 2")] == [10, 20]

    def test_tail_after_a_descending_sort(self) -> None:
        assert [r["sev"] for r in rows_of("search * | sort -sev | tail 3")] == [10, 20, 30]


class TestStats:
    """Grouping, ordering, and the functions splunkd offers."""

    def test_groups_come_back_sorted_by_the_by_fields(self) -> None:
        # Not in the order the events happened to arrive: a client rendering
        # the first row as "the top group" saw whichever host came first.
        rows = rows_of("search * | stats count by host")
        assert [r["host"] for r in rows] == ["srv-1", "srv-2", "srv-3"]

    def test_several_by_fields_sort_left_to_right(self) -> None:
        rows = rows_of("search * | stats count by host, action")
        assert [(r["host"], r["action"]) for r in rows] == [
            ("srv-1", "allow"), ("srv-1", "block"),
            ("srv-2", "allow"), ("srv-2", "block"),
            ("srv-3", "allow"),
        ]

    def test_a_row_without_the_by_field_joins_no_group(self) -> None:
        # `stats count by nope` returns nothing, not one group keyed on "".
        assert rows_of("search * | stats count by nope") == []

    @pytest.mark.parametrize(("function", "expected"), [
        ("stdev(sev)", 15.811388300841896),
        ("stdevp(sev)", 14.142135623730951),
        ("var(sev)", 250.0),
        ("varp(sev)", 200.0),
        ("sumsq(sev)", 5500.0),
        ("median(sev)", 30.0),
        ("perc95(sev)", 48.0),
        ("perc25(sev)", 20.0),
    ])
    def test_the_spread_statistics_splunk_documents(
        self, function: str, expected: float,
    ) -> None:
        # These reported "unknown stats function" — a dashboard asking for a
        # standard deviation got an error where splunkd answers a number.
        value = rows_of(f"search * | stats {function}")[0][function]
        assert float(value) == pytest.approx(expected)

    def test_earliest_and_latest_read_the_clock_not_the_pipeline(self) -> None:
        row = rows_of("search * | stats earliest(sev), latest(sev)")[0]
        assert (row["earliest(sev)"], row["latest(sev)"]) == (10, 50)

    def test_mode_is_the_most_frequent_value(self) -> None:
        rows = [{"x": v} for v in (1, 2, 2, 3)]
        assert rows_of("search * | stats mode(x)", rows)[0]["mode(x)"] == "2"


class TestTopAndRare:
    """The share of the whole, and the whole it is a share of."""

    def test_the_total_is_reported(self) -> None:
        # Without `_tc` a client cannot tell 3 of 5 from 3 of 3000.
        row = rows_of("search * | top action")[0]
        assert row["_tc"] == 5

    def test_the_percentage_carries_six_decimals(self) -> None:
        assert rows_of("search * | top action")[0]["percent"] == "60.000000"

    def test_options_are_options_and_not_field_names(self) -> None:
        # `showperc=f` used to be counted as a field, producing one bucket
        # keyed on the literal string.
        rows = rows_of("search * | top action showperc=f")
        assert "percent" not in rows[0]
        assert set(rows[0]) == {"action", "count", "_tc"}

    def test_showcount_false_drops_the_count(self) -> None:
        rows = rows_of("search * | top action showcount=f")
        assert set(rows[0]) == {"action", "percent", "_tc"}

    def test_rare_orders_the_other_way(self) -> None:
        assert [r["action"] for r in rows_of("search * | rare action")] == ["block", "allow"]


class TestTable:
    """A field a row does not have is dropped, not shown empty."""

    def test_a_field_no_row_has_yields_no_rows(self) -> None:
        rows, messages = run("search * | table nope")
        assert rows == []
        assert messages == [{"type": "INFO", "text": "No matching fields exist."}]

    def test_a_partly_present_field_is_dropped_per_row(self) -> None:
        rows = rows_of("search * | table host, nope")
        assert rows[0] == {"host": "srv-1"}

    def test_the_named_order_is_kept(self) -> None:
        assert list(rows_of("search * | table sev, host")[0]) == ["sev", "host"]


class TestEvalRounding:
    """`round` keeps the precision it was asked for."""

    @pytest.mark.parametrize(("expression", "expected"), [
        ("round(10,2)", "10.00"),
        ("round(3,3)", "3.000"),
        ("round(10.567,1)", "10.6"),
        # Splunk rounds a half away from zero; Python rounds it to even, so
        # `round(10.5)` was 10 here and 11 there.
        ("round(10.5)", 11),
        ("round(10.5,0)", 11),
    ])
    def test_round_matches_splunk(self, expression: str, expected: object) -> None:
        assert rows_of(f"search * | head 1 | eval r={expression} | table r")[0]["r"] == expected


class TestRenderedResults:
    """What the results envelope carries once the pipeline is done."""

    def test_time_is_rendered_as_iso_8601(self, splunk_client: TestClient) -> None:
        # Every SIEM integration parses `_time`; an epoch float here against
        # an ISO-8601 string in production only shows up in production.
        response = splunk_client.post(
            "/splunk/services/search/jobs",
            headers=splunk_auth(),
            data={"search": "search index=sentinelone | head 1", "output_mode": "json",
                  "exec_mode": "oneshot"},
        )
        stamp = response.json()["results"][0]["_time"]
        assert stamp.endswith("+00:00")
        assert stamp[10] == "T"

    def test_a_single_valued_field_is_a_string_not_a_list(
        self, splunk_client: TestClient,
    ) -> None:
        response = splunk_client.post(
            "/splunk/services/search/jobs",
            headers=splunk_auth(),
            data={"search": "search index=sentinelone | head 1 | stats values(index)",
                  "output_mode": "json", "exec_mode": "oneshot"},
        )
        assert response.json()["results"][0]["values(index)"] == "sentinelone"


def splunk_auth() -> dict[str, str]:
    """Basic credentials for the mock's Splunk mount."""
    return {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


@pytest.fixture
def splunk_client() -> object:
    """A client against the seeded app."""
    from main import app
    with TestClient(app) as client:
        yield client


