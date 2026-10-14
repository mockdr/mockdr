"""One request cannot buy unbounded work from a query engine.

Each case here was measured holding a worker for seconds to minutes, growing
the process by hundreds of megabytes, or answering 500, from a single
request with the documented mock credentials.
"""
from __future__ import annotations

import time

from utils.cs_fql import parse_fql
from utils.es_query import calculate_min_should_match
from utils.splunk.spl_exec import MAX_EXPANDED_ROWS, MAX_GENERATED_ROWS, execute_pipeline
from utils.splunk.spl_parser import parse_spl


def _spl(query: str) -> tuple[list, list]:
    return execute_pipeline([], parse_spl(query))


def test_deeply_grouped_fql_parses_in_linear_time() -> None:
    """Peeling one bracket pair per rescan was quadratic: 50,000 pairs took 96 s."""
    depth = 50_000
    started = time.perf_counter()
    clauses = parse_fql("(" * depth + "hostname:'x'" + ")" * depth)
    assert time.perf_counter() - started < 2
    assert [(c.field, c.values) for c in clauses] == [("hostname", ["x"])]


def test_fql_groups_that_do_not_enclose_the_term_are_kept() -> None:
    clauses = parse_fql("(status:'normal')+platform_name:'Windows'")
    assert {c.field for c in clauses} == {"status", "platform_name"}


def test_a_long_minimum_should_match_chain_is_no_recursion_error() -> None:
    spec = "0<" * 5_000 + "1"
    assert calculate_min_should_match(3, spec) == 1
    # Each link still applies only once there are more optional clauses.
    assert calculate_min_should_match(3, "5<1<2") == 3
    assert calculate_min_should_match(3, "1<5<2") == 3
    assert calculate_min_should_match(9, "1<5<2") == 2


def test_makeresults_generates_at_most_maxresultrows() -> None:
    rows, messages = _spl("| makeresults count=100000000")
    assert len(rows) == MAX_GENERATED_ROWS
    assert not messages


def test_mvrange_refuses_a_huge_range() -> None:
    rows, messages = _spl("| makeresults | eval x=mvrange(0, 10000000000)")
    assert rows == []
    assert messages[0]["type"] == "FATAL"


def test_mvrange_has_a_budget_across_rows() -> None:
    """50,000 rows each asking for 50,000 values ran for minutes."""
    started = time.perf_counter()
    rows, messages = _spl("| makeresults count=50000 | eval x=mvrange(0, 50000) | mvexpand x")
    assert time.perf_counter() - started < 5
    assert rows == []
    assert messages[0]["type"] == "FATAL"


def test_mvexpand_stops_at_its_ceiling() -> None:
    rows, _ = _spl("| makeresults count=20 | eval x=mvrange(0, 50000) | mvexpand x")
    assert len(rows) == MAX_EXPANDED_ROWS


def test_a_float_overflow_is_a_failed_search_not_a_crash() -> None:
    for expression in ("pow(10, 1000)", "exp(100000)"):
        rows, messages = _spl(f"| makeresults | eval x={expression}")
        assert rows == []
        assert messages[0]["type"] == "FATAL"
