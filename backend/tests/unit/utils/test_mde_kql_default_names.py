"""An aggregation nobody named is named the way KQL names it.

`summarize count()` produced a column called `count`; KQL calls it `count_`,
so a Defender hunting query copied into a test and reading `count_` found no
such column. `make_set(x)` was `make_set_x` where KQL says `set_x`, and a
`max` over a group without a single number answered 0 where KQL answers null.
Reference: https://learn.microsoft.com/en-us/kusto/query/summarize-operator
(the default-names examples and the "Default values of aggregations" table).
"""
import pytest

from utils.mde_kql import evaluate_kql, parse_kql

_ROWS = [
    {"OSPlatform": "Windows10", "RiskScore": "High", "Score": 3},
    {"OSPlatform": "Windows10", "RiskScore": "Low", "Score": 5},
    {"OSPlatform": "Linux", "RiskScore": "Low", "Score": None},
]


def _run(query: str) -> list[dict]:
    return evaluate_kql(_ROWS, parse_kql(query))


class TestDefaultNames:
    """Unaliased aggregations take KQL's default column names."""

    @pytest.mark.parametrize(("aggregation", "column"), [
        ("count()", "count_"),
        ("count(Score)", "count_Score"),
        ("dcount(RiskScore)", "dcount_RiskScore"),
        ("sum(Score)", "sum_Score"),
        ("avg(Score)", "avg_Score"),
        ("max(Score)", "max_Score"),
        ("make_set(RiskScore)", "set_RiskScore"),
        ("make_list(RiskScore)", "list_RiskScore"),
        ("take_any(RiskScore)", "any_RiskScore"),
    ])
    def test_the_column_is_named_as_kql_names_it(self, aggregation: str, column: str) -> None:
        rows = _run(f"T | summarize {aggregation} by OSPlatform")
        assert all(set(r) == {"OSPlatform", column} for r in rows)

    def test_an_alias_still_wins(self) -> None:
        assert set(_run("T | summarize Devices=count()")[0]) == {"Devices"}


class TestEmptyAggregates:
    """Over no numbers, only the summing aggregates are 0; the rest are null."""

    def test_max_over_no_numbers_is_null(self) -> None:
        linux = next(r for r in _run("T | summarize max(Score) by OSPlatform")
                     if r["OSPlatform"] == "Linux")
        assert linux["max_Score"] is None

    def test_sum_over_no_numbers_is_zero(self) -> None:
        linux = next(r for r in _run("T | summarize sum(Score) by OSPlatform")
                     if r["OSPlatform"] == "Linux")
        assert linux["sum_Score"] == 0
