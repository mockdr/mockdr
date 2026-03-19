"""Basic SPL (Search Processing Language) query parser.

Supports the subset of SPL that XSOAR SplunkPy actually sends:
- ``search index=<index> sourcetype=<sourcetype> <key>=<value>``
- ``| where <field>=<value>`` / ``| where <field>="<value>"``
- ``| head <N>`` / ``| tail <N>``
- ``| table <fields>``
- ``| stats count by <field>``
- ``| sort <field>`` / ``| sort -<field>``
- ``| rename <old> as <new>``
- ``| eval <field>=<expr>``
- Time modifiers: ``earliest=<time>`` ``latest=<time>``
- Notable macro: `` `notable` `` → ``search index=notable``

This is NOT a full SPL engine — it handles enough for SOAR integration testing.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


@dataclass
class SPLQuery:
    """Parsed SPL query components."""

    index: str = ""
    sourcetype: str = ""
    source: str = ""
    host: str = ""
    earliest_time: str = ""
    latest_time: str = ""
    field_filters: dict[str, str] = field(default_factory=dict)
    where_clauses: list[tuple[str, str]] = field(default_factory=list)
    head: int = 0
    tail: int = 0
    table_fields: list[str] = field(default_factory=list)
    stats_count_by: str = ""
    sort_field: str = ""
    sort_descending: bool = False
    renames: dict[str, str] = field(default_factory=dict)
    evals: dict[str, str] = field(default_factory=dict)
    raw_search: str = ""
    is_notable: bool = False


def parse_spl(query: str) -> SPLQuery:
    """Parse an SPL query string into structured components.

    Args:
        query: Raw SPL query string.

    Returns:
        Parsed ``SPLQuery`` dataclass.
    """
    result = SPLQuery(raw_search=query)

    # Expand the notable macro
    expanded = query.strip()
    if "`notable`" in expanded:
        expanded = expanded.replace("`notable`", "search index=notable")
        result.is_notable = True

    # Strip leading "search " if present
    if expanded.lower().startswith("search "):
        expanded = expanded[7:]

    # Split on pipe to get search clause and command pipeline
    parts = re.split(r"\s*\|\s*", expanded, maxsplit=1)
    search_clause = parts[0].strip()
    pipeline = parts[1] if len(parts) > 1 else ""

    # Parse the search clause (key=value pairs and free text)
    _parse_search_clause(search_clause, result)

    # Parse pipeline commands
    if pipeline:
        _parse_pipeline(pipeline, result)

    return result


def _parse_search_clause(clause: str, result: SPLQuery) -> None:
    """Extract index, sourcetype, and field filters from the search clause."""
    # Match key=value and key="quoted value" pairs
    kv_pattern = re.compile(r'(\w+)\s*=\s*"([^"]*)"|\b(\w+)\s*=\s*(\S+)')

    for match in kv_pattern.finditer(clause):
        if match.group(1):
            key, value = match.group(1), match.group(2)
        else:
            key, value = match.group(3), match.group(4)

        key_lower = key.lower()
        if key_lower == "index":
            result.index = value
        elif key_lower == "sourcetype":
            result.sourcetype = value
        elif key_lower == "source":
            result.source = value
        elif key_lower == "host":
            result.host = value
        elif key_lower == "earliest":
            result.earliest_time = value
        elif key_lower == "latest":
            result.latest_time = value
        else:
            result.field_filters[key] = value


def _parse_pipeline(pipeline: str, result: SPLQuery) -> None:
    """Parse piped commands in the SPL pipeline."""
    # Split on unquoted pipes
    commands = re.split(r"\s*\|\s*", pipeline)

    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue

        cmd_lower = cmd.lower()

        if cmd_lower.startswith("where "):
            _parse_where(cmd[6:], result)
        elif cmd_lower.startswith("head "):
            try:
                result.head = int(cmd[5:].strip())
            except ValueError:
                pass
        elif cmd_lower.startswith("tail "):
            try:
                result.tail = int(cmd[5:].strip())
            except ValueError:
                pass
        elif cmd_lower.startswith("table "):
            fields_str = cmd[6:].strip()
            result.table_fields = [f.strip() for f in re.split(r"[,\s]+", fields_str) if f.strip()]
        elif cmd_lower.startswith("stats "):
            _parse_stats(cmd[6:], result)
        elif cmd_lower.startswith("sort "):
            field_str = cmd[5:].strip()
            if field_str.startswith("-"):
                result.sort_descending = True
                result.sort_field = field_str[1:].strip()
            elif field_str.startswith("+"):
                result.sort_field = field_str[1:].strip()
            else:
                result.sort_field = field_str
        elif cmd_lower.startswith("rename "):
            _parse_rename(cmd[7:], result)
        elif cmd_lower.startswith("eval "):
            _parse_eval(cmd[5:], result)


def _parse_where(clause: str, result: SPLQuery) -> None:
    """Parse a where clause (field=value or field="value")."""
    match = re.match(r'(\w+)\s*=\s*"([^"]*)"', clause)
    if not match:
        match = re.match(r"(\w+)\s*=\s*(\S+)", clause)
    if match:
        result.where_clauses.append((match.group(1), match.group(2)))


def _parse_stats(clause: str, result: SPLQuery) -> None:
    """Parse stats command (only 'count by field' is supported)."""
    match = re.match(r"count\s+by\s+(\w+)", clause.strip(), re.IGNORECASE)
    if match:
        result.stats_count_by = match.group(1)


def _parse_rename(clause: str, result: SPLQuery) -> None:
    """Parse rename command: old as new."""
    match = re.match(r'(\S+)\s+[Aa][Ss]\s+(\S+)', clause.strip())
    if match:
        result.renames[match.group(1)] = match.group(2)


def _parse_eval(clause: str, result: SPLQuery) -> None:
    """Parse eval command: field=expression."""
    match = re.match(r'(\w+)\s*=\s*(.*)', clause.strip())
    if match:
        result.evals[match.group(1)] = match.group(2)


def resolve_relative_time(time_str: str) -> float:
    """Convert a Splunk relative time string to epoch seconds.

    Supports: ``-1h``, ``-24h``, ``-7d``, ``-30d``, ``now``,
    ``-1h@h`` (snap), epoch literals.

    Args:
        time_str: Splunk time modifier string.

    Returns:
        Epoch seconds as float.
    """
    if not time_str:
        return 0.0

    now = time.time()

    if time_str == "now":
        return now

    # Try epoch literal
    try:
        return float(time_str)
    except ValueError:
        pass

    # Strip snap modifier (@h, @d, etc.)
    base = re.sub(r"@[a-z]+$", "", time_str, flags=re.IGNORECASE)

    # Parse relative: -Nh, -Nd, -Nw, -Nm, -Ns
    match = re.match(r"^([+-]?)(\d+)([smhdw])$", base)
    if match:
        sign = -1 if match.group(1) == "-" or match.group(1) == "" else 1
        amount = int(match.group(2))
        unit = match.group(3)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
        offset = amount * multipliers.get(unit, 1)
        return now + (sign * offset)

    return 0.0
