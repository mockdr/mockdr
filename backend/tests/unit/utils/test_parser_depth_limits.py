"""Recursion bounds on the query parsers.

This branch added three recursive-descent parsers — SPL, KQL and the
Elasticsearch clause builder. Without a depth bound, a deeply parenthesised or
deeply nested expression exhausts the stack and the ``RecursionError`` escapes
as a plain-text 500: the same class of bug the branch set out to remove, only
introduced by the fix. Elasticsearch caps this itself with
``indices.query.bool.max_nested_depth`` for precisely this reason.

Found by fuzzing rather than by review, which is why the bound is pinned here.
"""
import pytest

from utils.es_query import ESQueryError, build_predicate
from utils.mde_kql import KqlError, evaluate_kql, parse_kql
from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_expr import SPLExprError, parse_where
from utils.splunk.spl_parser import parse_spl

DEPTHS = [200, 1000, 5000]
ROWS = [{"a": 1, "_raw": "x"}]


@pytest.mark.parametrize("depth", DEPTHS)
class TestParsersRefuseRunawayNesting:
    """Each parser raises its own error rather than blowing the stack."""

    def test_spl_where(self, depth: int) -> None:
        expression = "(" * depth + "a=1" + ")" * depth
        with pytest.raises(SPLExprError):
            parse_where(expression)

    def test_kql_where(self, depth: int) -> None:
        expression = "(" * depth + "a == 1" + ")" * depth
        with pytest.raises(KqlError):
            evaluate_kql(list(ROWS), parse_kql(f"T | where {expression}"))

    def test_es_bool_clause(self, depth: int) -> None:
        clause: dict = {"term": {"a": "b"}}
        for _ in range(depth):
            clause = {"bool": {"must": [clause]}}
        with pytest.raises(ESQueryError):
            build_predicate(clause)


class TestOrdinaryNestingStillWorks:
    """The bound must not reject expressions a client would really send."""

    def test_spl_accepts_reasonable_nesting(self) -> None:
        assert parse_where("((a=1) AND (b=2)) OR (c=3)") is not None

    def test_kql_accepts_reasonable_nesting(self) -> None:
        rows = [{"a": 1, "b": 2}]
        result = evaluate_kql(
            list(rows),
            parse_kql('T | where ((a == 1) and (b == 2)) or (a == 9)'),
        )
        assert len(result) == 1

    def test_es_accepts_reasonable_nesting(self) -> None:
        clause: dict = {"term": {"a": 1}}
        for _ in range(5):
            clause = {"bool": {"must": [clause]}}
        assert build_predicate(clause)({"a": 1}) is True


class TestRunawayNestingIsReportedNotRaised:
    """The SPL pipeline reports the failure instead of propagating it."""

    def test_pipeline_records_a_message(self) -> None:
        expression = "(" * 500 + "a=1" + ")" * 500
        _, messages = execute_pipeline(
            list(ROWS), parse_spl(f"search * | where {expression}"),
        )
        assert any("nested too deeply" in m["text"] for m in messages)
