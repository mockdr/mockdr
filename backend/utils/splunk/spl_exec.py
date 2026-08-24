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
from utils.splunk.spl_parser import SPLCommand, SPLQuery, parse_sort_keys

__all__ = ["execute_pipeline"]

Rows = list[dict[str, Any]]


#: How splunkd names each command in an error. `eval` is the odd one: it
#: reports as `EvalCommand`, where everything else is `'<name>' command`.
_COMMAND_LABELS: dict[str, str] = {"eval": "EvalCommand"}


def _command_label(name: str) -> str:
    """The subject of splunkd's "Error in ..." line for this command."""
    special = _COMMAND_LABELS.get(name)
    return f"'{special}'" if special else f"'{name}' command"


def _failure_text(command: SPLCommand, exc: Exception) -> str:
    """Word a command failure the way splunkd words it."""
    subject = _command_label(command.name)
    if isinstance(exc, SPLExprError):
        if exc.function:
            return (
                f"Error in {subject}: The '{exc.function}' function is "
                f"unsupported or undefined."
            )
        if exc.at:
            return (
                f"Error in {subject}: The expression is malformed. "
                f"An unexpected character is reached at '{exc.at}'."
            )
    return f"Error in {subject}: {exc}"


def execute_pipeline(rows: Rows, query: SPLQuery) -> tuple[Rows, list[dict[str, str]]]:
    """Run *query*'s commands over *rows*, in order.

    Returns:
        The resulting rows and any messages produced along the way, each with
        the severity splunkd gives it. A command that cannot run at all is
        FATAL and takes the whole result set with it — returning the rows the
        pipeline had reached reads as an answer, and splunkd returns none.
    """
    if query.unknown_command:
        # splunkd refuses this dispatch rather than running the stages it did
        # recognise; the API layer turns it into the 400 it answers with.
        return [], [{
            "type": "FATAL",
            "text": f"Unknown search command '{query.unknown_command}'.",
        }]

    messages: list[dict[str, str]] = [
        {"type": "WARN", "text": text} for text in query.errors
    ]

    # The search clause is the first stage of the pipeline. Applying it here
    # keeps selection and the commands in one place, so the two cannot drift.
    if query.search_expr is not None:
        rows = [r for r in rows if evaluate(query.search_expr, r, mode="search")]

    for command in query.commands:
        handler = _HANDLERS.get(command.name)
        if handler is None:  # pragma: no cover - parser filters these out
            messages.append({
                "type": "FATAL", "text": f"Unknown search command '{command.name}'.",
            })
            return [], messages
        try:
            before = rows
            rows = handler(rows, command)
            if command.name == "table" and before and not rows:
                messages.append({"type": "INFO", "text": "No matching fields exist."})
        except (SPLExprError, ValueError, TypeError, KeyError, IndexError) as exc:
            messages.append({"type": "FATAL", "text": _failure_text(command, exc)})
            return [], messages
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
    """The last N results, in reverse order — which is what `tail` documents.

    Returning them in pipeline order made `| sort sev | tail 2` answer
    ascending where splunkd answers descending, so a client reading the first
    row as "the largest" got the smallest.
    """
    return rows[-_count(command.arg, default=10):][::-1]


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
    """Keep the named fields, and only where a row actually has them.

    splunkd drops a field a row does not carry rather than showing it empty,
    and when no row carries any of them it emits no rows at all. Inventing an
    empty column let a client believe the field exists and is blank.
    """
    fields = _fields(command.arg)
    if not fields:
        return rows
    if not any(field in row for row in rows for field in fields):
        return []
    return [{f: row[f] for f in fields if f in row} for row in rows]


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
    keys = parse_sort_keys(command.arg)
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
        # A row that does not carry every by-field is not part of any group:
        # `stats count by nope` returns nothing, not one group keyed on "".
        if any(row.get(f) in (None, "") for f in by_fields):
            continue
        key = tuple(str(row[f]) for f in by_fields)
        groups.setdefault(key, []).append(row)

    out: Rows = []
    # splunkd returns the groups sorted by the by-fields, not in the order the
    # events happened to arrive: `stats count by host` always reads srv-1,
    # srv-2, srv-3. A client rendering the first row as "the top group" saw
    # whichever host the search hit first.
    for key in sorted(groups, key=lambda k: tuple(_sortable(v) for v in k)):
        members = groups[key]
        record: dict[str, Any] = dict(zip(by_fields, key, strict=False))
        for func, field, alias in aggs:
            record[alias] = _aggregate(func, field, members)
        out.append(record)
    return out


def _sortable(value: str) -> tuple[int, float, str]:
    """Order a group key numerically when it is a number, lexically otherwise."""
    try:
        return (0, float(value), "")
    except (TypeError, ValueError):
        return (1, 0.0, str(value))


def _cmd_top(rows: Rows, command: SPLCommand) -> Rows:
    return _top_or_rare(rows, command, most_common=True)


def _cmd_rare(rows: Rows, command: SPLCommand) -> Rows:
    return _top_or_rare(rows, command, most_common=False)


#: `top`'s and `rare`'s options, which are not field names — reading them as
#: fields counted a bucket keyed on the literal string "showperc=f".
_TOP_OPTION_RE = re.compile(
    r"\b(limit|showcount|showperc|countfield|percentfield|useother|otherstr)"
    r"\s*=\s*\S+", re.I,
)


def _top_or_rare(rows: Rows, command: SPLCommand, *, most_common: bool) -> Rows:
    arg = command.arg.strip()
    limit = _leading_count(arg) or 10
    limit_match = re.search(r"limit\s*=\s*(\d+)", arg, re.I)
    if limit_match:
        limit = int(limit_match.group(1))
    show_count = not re.search(r"showcount\s*=\s*(?:f|false|0)\b", arg, re.I)
    show_percent = not re.search(r"showperc\s*=\s*(?:f|false|0)\b", arg, re.I)

    fields = _fields(re.sub(r"^\s*\d+\s+", "", _TOP_OPTION_RE.sub("", arg)))
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
        if show_count:
            record["count"] = count
        if show_percent:
            # splunkd renders the share with six decimals, always: `60.000000`.
            record["percent"] = f"{count * 100.0 / total:.6f}"
        # The total the shares are of. Absent here, a client could not tell
        # 3 of 5 from 3 of 3000.
        record["_tc"] = total
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

#: `perc95(x)`, `p95(x)` and `upperperc95(x)` all name the same statistic on
#: a single search head.
_PERCENTILE_RE = re.compile(r"(?:upper|lower)?perc(\d+(?:\.\d+)?)|p(?:erc)?(\d+(?:\.\d+)?)")


def _percentile(numbers: list[float], percent: float) -> float:
    """The percentile Splunk reports: linear interpolation between ranks."""
    ordered = sorted(numbers)
    if len(ordered) == 1:
        return ordered[0]
    position = (percent / 100.0) * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (position - lower) * (ordered[upper] - ordered[lower])


def _variance(numbers: list[float], *, population: bool) -> float:
    """Variance over the sample (n-1) or the population (n)."""
    count = len(numbers)
    divisor = count if population else count - 1
    if divisor <= 0:
        return 0.0
    mean = sum(numbers) / count
    return sum((n - mean) ** 2 for n in numbers) / divisor


#: The spread statistics Splunk documents, which the mock reported as unknown
#: functions — a dashboard asking for a standard deviation got a FATAL where
#: splunkd answers with a number.
_SPREAD_FUNCTIONS: dict[str, Callable[[list[float]], float]] = {
    "stdev": lambda ns: _variance(ns, population=False) ** 0.5,
    "stdevp": lambda ns: _variance(ns, population=True) ** 0.5,
    "var": lambda ns: _variance(ns, population=False),
    "varp": lambda ns: _variance(ns, population=True),
    "sumsq": lambda ns: sum(n * n for n in ns),
}


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

    if name in ("earliest", "latest"):
        # By event time, not pipeline order — which is what separates these
        # from `first` and `last`.
        timed = [r for r in rows if r.get(field) not in (None, "")]
        if not timed:
            return ""
        by_time = sorted(timed, key=lambda r: _as_float(r.get("_time")) or 0.0)
        return by_time[0 if name == "earliest" else -1].get(field)

    numbers = [n for n in (_as_float(r.get(field)) for r in rows) if n is not None]
    if name == "mode":
        values = [str(r.get(field)) for r in rows if r.get(field) not in (None, "")]
        if not values:
            return ""
        counts = Counter(values)
        best = max(counts.values())
        return sorted(v for v, c in counts.items() if c == best)[0]
    if numbers and name in _SPREAD_FUNCTIONS:
        return _SPREAD_FUNCTIONS[name](numbers)
    percentile = _PERCENTILE_RE.fullmatch(name)
    if percentile and numbers:
        return _percentile(numbers, float(percentile.group(1)))
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
