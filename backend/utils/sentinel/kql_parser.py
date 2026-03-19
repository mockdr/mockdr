"""Basic KQL (Kusto Query Language) parser.

Supports the subset of KQL that SOAR integrations actually send:
- ``SecurityIncident | where Status == "New" | take 50``
- ``SecurityAlert | where TimeGenerated > ago(24h)``
- ``| project Title, Severity, Status``
- ``| sort by CreatedTime desc``
- ``| summarize count() by Severity``
- ``| extend CustomField = strcat(Title, " - ", Severity)``
- ``| where Severity in ("High", "Medium")``
- ``union SecurityIncident, SecurityAlert``

This is NOT a full KQL engine.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


@dataclass
class KQLQuery:
    """Parsed KQL query components."""

    tables: list[str] = field(default_factory=list)
    where_clauses: list[tuple[str, str, str]] = field(default_factory=list)  # (field, op, value)
    where_in_clauses: list[tuple[str, list[str]]] = field(default_factory=list)
    project_fields: list[str] = field(default_factory=list)
    sort_field: str = ""
    sort_descending: bool = True
    take: int = 0
    summarize_func: str = ""
    summarize_by: str = ""
    extend_fields: dict[str, str] = field(default_factory=dict)
    ago_filters: list[tuple[str, float]] = field(default_factory=list)  # (field, epoch_threshold)
    raw_query: str = ""


def parse_kql(query: str) -> KQLQuery:
    """Parse a KQL query string into structured components.

    Args:
        query: Raw KQL query string.

    Returns:
        Parsed ``KQLQuery`` dataclass.
    """
    result = KQLQuery(raw_query=query)
    query = query.strip()

    # Handle union: union Table1, Table2
    if query.lower().startswith("union "):
        union_part, _, rest = query.partition("|")
        tables_str = union_part[6:].strip()
        result.tables = [t.strip() for t in tables_str.split(",") if t.strip()]
        query = rest.strip() if rest else ""
    else:
        # First token is the table name
        parts = query.split("|", 1)
        table_name = parts[0].strip()
        if table_name:
            result.tables = [table_name]
        query = parts[1].strip() if len(parts) > 1 else ""

    # Parse pipeline operators
    if query:
        _parse_pipeline(query, result)

    return result


def _parse_pipeline(pipeline: str, result: KQLQuery) -> None:
    """Parse piped KQL operators."""
    commands = re.split(r"\s*\|\s*", pipeline)

    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue

        cmd_lower = cmd.lower()

        if cmd_lower.startswith("where "):
            _parse_where(cmd[6:], result)
        elif cmd_lower.startswith("take ") or cmd_lower.startswith("limit "):
            token = cmd.split(None, 1)[1].strip()
            try:
                result.take = int(token)
            except ValueError:
                pass
        elif cmd_lower.startswith("top "):
            match = re.match(r"top\s+(\d+)", cmd, re.IGNORECASE)
            if match:
                result.take = int(match.group(1))
        elif cmd_lower.startswith("project "):
            fields_str = cmd[8:].strip()
            result.project_fields = [f.strip() for f in fields_str.split(",") if f.strip()]
        elif cmd_lower.startswith("sort by ") or cmd_lower.startswith("order by "):
            _parse_sort(cmd, result)
        elif cmd_lower.startswith("summarize "):
            _parse_summarize(cmd[10:], result)
        elif cmd_lower.startswith("extend "):
            _parse_extend(cmd[7:], result)


def _parse_where(clause: str, result: KQLQuery) -> None:
    """Parse a where clause."""
    clause = clause.strip()

    # Handle: field in ("val1", "val2")
    in_match = re.match(
        r'(\w+)\s+in\s*\(\s*(.*?)\s*\)',
        clause, re.IGNORECASE,
    )
    if in_match:
        field_name = in_match.group(1)
        values_str = in_match.group(2)
        values = [v.strip().strip('"').strip("'") for v in values_str.split(",")]
        result.where_in_clauses.append((field_name, values))
        return

    # Handle: field > ago(24h)
    ago_match = re.match(
        r'(\w+)\s*>\s*ago\((\d+)([smhd])\)',
        clause, re.IGNORECASE,
    )
    if ago_match:
        field_name = ago_match.group(1)
        amount = int(ago_match.group(2))
        unit = ago_match.group(3)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        threshold = time.time() - (amount * multipliers.get(unit, 1))
        result.ago_filters.append((field_name, threshold))
        return

    # Handle: field == "value" or field == value or field != "value"
    eq_match = re.match(r'(\w+)\s*(==|!=|>=|<=|>|<)\s*"?([^"]*)"?', clause)
    if eq_match:
        result.where_clauses.append((
            eq_match.group(1),
            eq_match.group(2),
            eq_match.group(3).strip(),
        ))


def _parse_sort(cmd: str, result: KQLQuery) -> None:
    """Parse sort/order by clause."""
    match = re.match(r'(?:sort|order)\s+by\s+(\w+)(?:\s+(asc|desc))?', cmd, re.IGNORECASE)
    if match:
        result.sort_field = match.group(1)
        result.sort_descending = (match.group(2) or "desc").lower() == "desc"


def _parse_summarize(clause: str, result: KQLQuery) -> None:
    """Parse summarize clause (only count() by field supported)."""
    match = re.match(r'count\(\)\s+by\s+(\w+)', clause.strip(), re.IGNORECASE)
    if match:
        result.summarize_func = "count"
        result.summarize_by = match.group(1)


def _parse_extend(clause: str, result: KQLQuery) -> None:
    """Parse extend clause: field = expression."""
    match = re.match(r'(\w+)\s*=\s*(.*)', clause.strip())
    if match:
        result.extend_fields[match.group(1)] = match.group(2)
