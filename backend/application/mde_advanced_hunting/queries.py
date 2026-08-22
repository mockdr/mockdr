"""Microsoft Defender for Endpoint Advanced Hunting query handler."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from application.mde_advanced_hunting.tables import TABLE_NAMES, get_table
from utils.mde_kql import KqlError, evaluate_kql, parse_kql

__all__ = ["run_query"]

#: Column types Defender reports in the response Schema.
_TYPE_NAMES: dict[type, str] = {
    bool: "Boolean",
    int: "Int64",
    float: "Double",
    str: "String",
    list: "SByte",
    dict: "SByte",
}


def run_query(body: dict) -> dict:
    """Execute an Advanced Hunting KQL query against the seeded tables.

    The query used to be accepted and never evaluated — every request returned
    the same three synthetic rows, so a query naming a nonexistent table, or
    carrying a ``where`` that excludes everything, still came back with
    results and told a detection engineer nothing.

    Args:
        body: Request body containing ``Query`` (a KQL string).

    Returns:
        Advanced hunting response with ``Schema``, ``Results`` and ``Stats``.

    Raises:
        KqlError: If the query cannot be parsed or names an unknown table.
    """
    query = parse_kql(body.get("Query", ""))

    rows = get_table(query.table)
    if rows is None:
        msg = (
            f"A recognized table name is expected, found '{query.table}'. "
            f"Tables available in this mock: {', '.join(TABLE_NAMES)}"
        )
        raise KqlError(msg)

    results = evaluate_kql(rows, query)
    return {
        "Schema": _schema_for(results, rows),
        "Results": results,
        "Stats": {
            "ExecutionTime": 0.05,
            "resource_usage": {"cache": {"memory": {"hits": 0, "misses": 0}}},
            "dataset_statistics": [{"table_row_count": len(results)}],
        },
    }


def _schema_for(results: list[dict], source: list[dict]) -> list[dict[str, str]]:
    """Describe the columns of *results*, falling back to the source table.

    A query that filters everything out still has a schema, because the
    projection is decided by the query rather than by what survived it.
    """
    sample = results[0] if results else {}
    if not sample and source:
        sample = source[0]
    return [{"Name": name, "Type": _type_name(value)} for name, value in sample.items()]


def _type_name(value: Any) -> str:
    if isinstance(value, str) and _looks_like_datetime(value):
        return "DateTime"
    return _TYPE_NAMES.get(type(value), "String")


def _looks_like_datetime(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True
