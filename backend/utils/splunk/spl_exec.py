"""Executes a parsed SPL pipeline against a list of rows.

Commands run in the order they were written, which is how Splunk behaves and
what makes ``| head 1 | sort _time`` differ from ``| sort _time | head 1``.
The previous implementation applied a fixed sequence regardless of the query
text, so the two forms returned different rows than Splunk would.
"""
from __future__ import annotations

import re
from collections import Counter, OrderedDict
from collections.abc import Callable
from typing import Any

from utils.splunk.spl_expr import (
    SPLExprError,
    evaluate,
    parse_eval,
    parse_search,
    parse_where,
)
from utils.splunk.spl_parser import SPLCommand, SPLQuery

__all__ = ["execute_pipeline"]

Rows = list[dict[str, Any]]


def execute_pipeline(rows: Rows, query: SPLQuery) -> tuple[Rows, list[str]]:
    """Run *query*'s commands over *rows*, in order.

    Returns:
        The resulting rows and any diagnostic messages produced along the way.
    """
    messages: list[str] = list(query.errors)

    # The search clause is the first stage of the pipeline. Applying it here
    # keeps selection and the commands in one place, so the two cannot drift.
    if query.search_expr is not None:
        rows = [r for r in rows if evaluate(query.search_expr, r, mode="search")]

    for command in query.commands:
        handler = _HANDLERS.get(command.name)
        if handler is None:  # pragma: no cover - parser filters these out
            messages.append(f"Unknown search command '{command.name}'.")
            continue
        try:
            rows = handler(rows, command)
        except SPLExprError as exc:
            messages.append(f"Error in '{command.name}' command: {exc}")
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            messages.append(f"Error in '{command.name}' command: {exc}")
    return rows, messages


# ---------------------------------------------------------------------------
# Filtering commands
# ---------------------------------------------------------------------------

def _cmd_search(rows: Rows, command: SPLCommand) -> Rows:
    node = parse_search(command.arg)
    return [r for r in rows if evaluate(node, r, mode="search")]


def _cmd_where(rows: Rows, command: SPLCommand) -> Rows:
    node = parse_where(command.arg)
    return [r for r in rows if evaluate(node, r, mode="where")]


def _cmd_regex(rows: Rows, command: SPLCommand) -> Rows:
    match = re.match(r'\s*(\w+)\s*(!?=)\s*"?(.*?)"?\s*$', command.arg)
    if not match:
        pattern = re.compile(command.arg.strip().strip('"'))
        return [r for r in rows if pattern.search(str(r.get("_raw", "")))]
    field, op, raw_pattern = match.groups()
    pattern = re.compile(raw_pattern)
    negate = op == "!="
    return [
        r for r in rows
        if bool(pattern.search(str(r.get(field, "")))) is not negate
    ]


def _cmd_head(rows: Rows, command: SPLCommand) -> Rows:
    return rows[: _count(command.arg, default=10)]


def _cmd_tail(rows: Rows, command: SPLCommand) -> Rows:
    return rows[-_count(command.arg, default=10) :]


def _cmd_dedup(rows: Rows, command: SPLCommand) -> Rows:
    fields = _fields(command.arg)
    if not fields:
        return rows
    seen: set[tuple] = set()
    kept: Rows = []
    for row in rows:
        key = tuple(str(row.get(f, "")) for f in fields)
        if key not in seen:
            seen.add(key)
            kept.append(row)
    return kept


# ---------------------------------------------------------------------------
# Shaping commands
# ---------------------------------------------------------------------------

def _cmd_table(rows: Rows, command: SPLCommand) -> Rows:
    fields = _fields(command.arg)
    return [{f: row.get(f, "") for f in fields} for row in rows]


def _cmd_fields(rows: Rows, command: SPLCommand) -> Rows:
    arg = command.arg.strip()
    remove = arg.startswith("-")
    fields = _fields(arg.lstrip("+-"))
    if not fields:
        return rows
    if remove:
        return [{k: v for k, v in row.items() if k not in fields} for row in rows]
    return [
        {k: v for k, v in row.items() if k in fields}
        for row in rows
    ]


def _cmd_rename(rows: Rows, command: SPLCommand) -> Rows:
    mapping: dict[str, str] = {}
    for clause in command.arg.split(","):
        match = re.match(r'\s*"?([^"]+?)"?\s+as\s+"?([^"]+?)"?\s*$', clause, re.I)
        if match:
            mapping[match.group(1)] = match.group(2)
    if not mapping:
        return rows
    return [
        {mapping.get(key, key): value for key, value in row.items()}
        for row in rows
    ]


def _cmd_eval(rows: Rows, command: SPLCommand) -> Rows:
    assignments: list[tuple[str, Any]] = []
    for clause in _split_eval_clauses(command.arg):
        match = re.match(r"\s*(\w+)\s*=\s*(.+)$", clause, re.DOTALL)
        if not match:
            msg = f"invalid eval expression {clause.strip()!r}"
            raise SPLExprError(msg)
        assignments.append((match.group(1), parse_eval(match.group(2))))

    out: Rows = []
    for row in rows:
        updated = dict(row)
        for name, node in assignments:
            updated[name] = evaluate(node, updated, mode="eval")
        out.append(updated)
    return out


def _cmd_fillnull(rows: Rows, command: SPLCommand) -> Rows:
    match = re.search(r'value\s*=\s*"?([^"\s]+)"?', command.arg, re.I)
    filler: Any = match.group(1) if match else 0
    remainder = re.sub(r'value\s*=\s*"?[^"\s]+"?', "", command.arg, flags=re.I)
    fields = _fields(remainder)
    out: Rows = []
    for row in rows:
        updated = dict(row)
        targets = fields or list(updated)
        for field in targets:
            if updated.get(field) in (None, ""):
                updated[field] = filler
        out.append(updated)
    return out


def _cmd_rex(rows: Rows, command: SPLCommand) -> Rows:
    field_match = re.search(r'field\s*=\s*(\S+)', command.arg, re.I)
    source_field = field_match.group(1).strip('"') if field_match else "_raw"
    pattern_match = re.search(r'"((?:[^"\\]|\\.)*)"', command.arg)
    if not pattern_match:
        msg = "rex requires a quoted regular expression"
        raise SPLExprError(msg)
    expression = pattern_match.group(1).replace('\\"', '"')
    # Splunk spells named groups (?<name>...); Python requires (?P<name>...).
    expression = re.sub(r"\(\?<(?![=!])", "(?P<", expression)
    pattern = re.compile(expression)

    out: Rows = []
    for row in rows:
        updated = dict(row)
        found = pattern.search(str(row.get(source_field, "")))
        if found:
            updated.update({k: v for k, v in found.groupdict().items() if v is not None})
        out.append(updated)
    return out


def _cmd_sort(rows: Rows, command: SPLCommand) -> Rows:
    from utils.splunk.spl_parser import _parse_sort  # noqa: PLC0415 - avoids a cycle

    keys = _parse_sort(command.arg)
    if not keys:
        return rows
    limit = _leading_count(command.arg)
    ordered = list(rows)
    # Sort least-significant key first so earlier keys win, and compare
    # numerically where both sides are numbers — a lexicographic sort put
    # "120" before "20".
    for field, descending in reversed(keys):
        ordered.sort(key=_sorter(field), reverse=descending)
    return ordered[:limit] if limit else ordered


# ---------------------------------------------------------------------------
# Aggregating commands
# ---------------------------------------------------------------------------

_AGG_RE = re.compile(
    r"(?P<func>\w+)\s*\(\s*(?P<field>[^)]*)\s*\)(?:\s+as\s+(?P<alias>\S+))?"
    r"|(?P<bare>\bcount\b)(?:\s+as\s+(?P<bare_alias>\S+))?",
    re.IGNORECASE,
)


def _cmd_stats(rows: Rows, command: SPLCommand) -> Rows:
    agg_text, by_fields = _split_by(command.arg)
    aggs = _parse_aggregations(agg_text)
    if not aggs:
        aggs = [("count", "", "count")]

    groups: OrderedDict[tuple, Rows] = OrderedDict()
    for row in rows:
        key = tuple(str(row.get(f, "")) for f in by_fields)
        groups.setdefault(key, []).append(row)

    out: Rows = []
    for key, members in groups.items():
        record: dict[str, Any] = dict(zip(by_fields, key, strict=False))
        for func, field, alias in aggs:
            record[alias] = _aggregate(func, field, members)
        out.append(record)
    return out


def _cmd_top(rows: Rows, command: SPLCommand) -> Rows:
    return _top_or_rare(rows, command, most_common=True)


def _cmd_rare(rows: Rows, command: SPLCommand) -> Rows:
    return _top_or_rare(rows, command, most_common=False)


def _top_or_rare(rows: Rows, command: SPLCommand, *, most_common: bool) -> Rows:
    arg = command.arg.strip()
    limit = _leading_count(arg) or 10
    limit_match = re.search(r"limit\s*=\s*(\d+)", arg, re.I)
    if limit_match:
        limit = int(limit_match.group(1))
        arg = re.sub(r"limit\s*=\s*\d+", "", arg, flags=re.I)
    fields = _fields(re.sub(r"^\s*\d+\s+", "", arg))
    if not fields:
        return rows

    counter = Counter(tuple(str(r.get(f, "")) for f in fields) for r in rows)
    total = sum(counter.values()) or 1
    ordered = counter.most_common()
    if not most_common:
        ordered = sorted(counter.items(), key=lambda kv: (kv[1], kv[0]))

    out: Rows = []
    for key, count in ordered[:limit]:
        record: dict[str, Any] = dict(zip(fields, key, strict=False))
        record["count"] = count
        record["percent"] = round(count * 100.0 / total, 6)
        out.append(record)
    return out


def _cmd_timechart(rows: Rows, command: SPLCommand) -> Rows:
    agg_text, by_fields = _split_by(command.arg)
    span = _span_seconds(agg_text)
    agg_text = re.sub(r"span\s*=\s*\S+", "", agg_text, flags=re.I)
    aggs = _parse_aggregations(agg_text) or [("count", "", "count")]

    buckets: OrderedDict[float, Rows] = OrderedDict()
    for row in rows:
        stamp = _as_float(row.get("_time"))
        bucket = (stamp // span) * span if stamp is not None else 0.0
        buckets.setdefault(bucket, []).append(row)

    out: Rows = []
    for bucket in sorted(buckets):
        record: dict[str, Any] = {"_time": str(bucket)}
        members = buckets[bucket]
        if by_fields:
            field = by_fields[0]
            for value in sorted({str(r.get(field, "")) for r in members}):
                subset = [r for r in members if str(r.get(field, "")) == value]
                record[value] = _aggregate(aggs[0][0], aggs[0][1], subset)
        else:
            for func, field, alias in aggs:
                record[alias] = _aggregate(func, field, members)
        out.append(record)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _aggregate(func: str, field: str, rows: Rows) -> Any:
    name = func.lower()
    if name in ("count", "c"):
        if not field:
            return len(rows)
        return sum(1 for r in rows if r.get(field) not in (None, ""))
    if name in ("dc", "distinct_count"):
        return len({str(r.get(field, "")) for r in rows})
    if name == "values":
        return sorted({str(r.get(field, "")) for r in rows if r.get(field) not in (None, "")})
    if name == "list":
        return [str(r.get(field, "")) for r in rows if r.get(field) not in (None, "")]
    if name in ("first", "last"):
        pool = [r.get(field) for r in rows if r.get(field) not in (None, "")]
        if not pool:
            return ""
        return pool[0] if name == "first" else pool[-1]

    numbers = [n for n in (_as_float(r.get(field)) for r in rows) if n is not None]
    if not numbers:
        return 0
    if name == "sum":
        return _shrink(sum(numbers))
    if name in ("avg", "mean"):
        return _shrink(sum(numbers) / len(numbers))
    if name == "min":
        return _shrink(min(numbers))
    if name == "max":
        return _shrink(max(numbers))
    if name == "range":
        return _shrink(max(numbers) - min(numbers))
    if name == "median":
        ordered = sorted(numbers)
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return _shrink(ordered[mid])
        return _shrink((ordered[mid - 1] + ordered[mid]) / 2)
    msg = f"unknown stats function {func!r}"
    raise SPLExprError(msg)


def _parse_aggregations(text: str) -> list[tuple[str, str, str]]:
    """Parse ``count``, ``sum(x)``, ``avg(y) as mean`` into (func, field, alias)."""
    aggs: list[tuple[str, str, str]] = []
    for match in _AGG_RE.finditer(text):
        if match.group("bare"):
            aggs.append(("count", "", match.group("bare_alias") or "count"))
            continue
        func = match.group("func").lower()
        field = (match.group("field") or "").strip()
        alias = match.group("alias") or (f"{func}({field})" if field else func)
        aggs.append((func, field, alias.strip('"')))
    return aggs


def _split_by(arg: str) -> tuple[str, list[str]]:
    match = re.search(r"\bby\s+(.+)$", arg, re.IGNORECASE)
    if not match:
        return arg, []
    return arg[: match.start()], _fields(match.group(1))


def _span_seconds(text: str) -> float:
    match = re.search(r"span\s*=\s*(\d+)([smhdw])", text, re.I)
    if not match:
        return 3600.0
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2).lower()]
    return float(int(match.group(1)) * unit)


def _fields(text: str) -> list[str]:
    return [
        f.strip().strip('"')
        for f in re.split(r"[,\s]+", text.strip())
        if f.strip() and f.strip().lower() != "by"
    ]


def _count(arg: str, *, default: int) -> int:
    match = re.search(r"-?\d+", arg or "")
    return int(match.group()) if match else default


def _leading_count(arg: str) -> int:
    match = re.match(r"\s*(\d+)\s+", arg or "")
    return int(match.group(1)) if match else 0


def _split_eval_clauses(arg: str) -> list[str]:
    """Split ``a=1, b=2`` on commas that are not inside quotes or parentheses."""
    clauses: list[str] = []
    current: list[str] = []
    depth = 0
    in_quotes = False
    for char in arg:
        if char == '"':
            in_quotes = not in_quotes
        elif not in_quotes and char == "(":
            depth += 1
        elif not in_quotes and char == ")":
            depth = max(depth - 1, 0)
        elif char == "," and not in_quotes and depth == 0:
            clauses.append("".join(current))
            current = []
            continue
        current.append(char)
    clauses.append("".join(current))
    return [c for c in clauses if c.strip()]


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _shrink(value: float) -> float | int:
    return int(value) if float(value).is_integer() else round(value, 6)


def _sorter(field: str) -> Callable[[dict[str, Any]], tuple[int, float, str]]:
    """Build a sort key function bound to *field*."""
    def key(row: dict[str, Any]) -> tuple[int, float, str]:
        return _sort_key(row.get(field))
    return key


def _sort_key(value: Any) -> tuple[int, float, str]:
    """Sort numerically when possible, so "20" precedes "120"."""
    number = _as_float(value)
    if number is not None:
        return (0, number, "")
    return (1, 0.0, str(value if value is not None else ""))


_HANDLERS: dict[str, Callable[[Rows, SPLCommand], Rows]] = {
    "dedup": _cmd_dedup,
    "eval": _cmd_eval,
    "fields": _cmd_fields,
    "fillnull": _cmd_fillnull,
    "head": _cmd_head,
    "rare": _cmd_rare,
    "regex": _cmd_regex,
    "rename": _cmd_rename,
    "rex": _cmd_rex,
    "search": _cmd_search,
    "sort": _cmd_sort,
    "stats": _cmd_stats,
    "table": _cmd_table,
    "tail": _cmd_tail,
    "timechart": _cmd_timechart,
    "top": _cmd_top,
    "where": _cmd_where,
}
