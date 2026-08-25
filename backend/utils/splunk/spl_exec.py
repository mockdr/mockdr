"""Executes a parsed SPL pipeline against a list of rows.

Commands run in the order they were written, which is how Splunk behaves and
what makes ``| head 1 | sort _time`` differ from ``| sort _time | head 1``.
The previous implementation applied a fixed sequence regardless of the query
text, so the two forms returned different rows than Splunk would.
"""
from __future__ import annotations

import csv
import io
import json
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
from utils.splunk.spl_parser import (
    SPLCommand,
    SPLQuery,
    current_time,
    parse_sort_keys,
)

__all__ = ["aggregation_aliases", "execute_pipeline", "split_by"]

Rows = list[dict[str, Any]]

#: The name this instance answers with, kept the same as the one
#: ``/services/server/info`` reports; `makeresults annotate=true` shows it.
SPLUNK_SERVER = "mockdr-splunk"


#: How splunkd names each command in an error. `eval` is the odd one: it
#: reports as `EvalCommand`, where everything else is `'<name>' command`.
_COMMAND_LABELS: dict[str, str] = {"eval": "EvalCommand"}


def _command_label(name: str) -> str:
    """The subject of splunkd's "Error in ..." line for this command."""
    special = _COMMAND_LABELS.get(name)
    return f"'{special}'" if special else f"'{name}' command"


def _failure_text(command: SPLCommand, exc: Exception) -> str:
    """Word a command failure the way splunkd words it."""
    if isinstance(exc, OptionError):
        return f"Error in '{exc.subject}': {exc}" if exc.subject else str(exc)
    subject = _command_label(command.name)
    if isinstance(exc, SPLExprError):
        if exc.function and exc.invalid_arguments:
            return (
                f"Error in {subject}: The arguments to the '{exc.function}' "
                f"function are invalid."
            )
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

    for position, command in enumerate(query.commands):
        if command.name == "makeresults" and (
            position or query.search_expr is not None
        ):
            # A generating command produces the rows; it cannot follow rows
            # that already exist.
            messages.append({
                "type": "FATAL",
                "text": (
                    "Error in 'makeresults' command: This command must be "
                    "the first command of a search."
                ),
            })
            return [], messages
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


# ---------------------------------------------------------------------------
# streamstats
#
# stats over the rows seen so far, added to each row as it passes. The mock
# refused it as an unknown command, which is honest but leaves out one of the
# handful of commands SIEM content actually uses — every "count events since"
# and "compare to the previous row" search is built on it.
#
# Measured against Splunk 10.4.2: `current=f` looks only at the rows before
# this one, `window=N` at the last N, `reset_on_change` starts again when the
# by-fields change, and `reset_before`/`reset_after` when an expression holds.
# ---------------------------------------------------------------------------

#: The options it takes. Anything else `key=value` is refused by name.
_STREAMSTATS_OPTIONS = frozenset({
    "window", "current", "global", "allnum", "reset_on_change",
    "reset_before", "reset_after", "time_window",
})


#: `1h`, `30m`, `2d` — the duration `time_window` takes.
_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([smhdw])?", re.IGNORECASE)

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _duration_seconds(text: str) -> float:
    """A ``time_window`` value in seconds; bare digits are seconds."""
    match = _DURATION_RE.fullmatch(text.strip())
    if not match:
        return 0.0
    unit = _DURATION_UNITS[(match.group(2) or "s").lower()]
    return float(match.group(1)) * unit


def _time_ordered(rows: Rows) -> bool:
    """Whether the rows run in time order, in either direction.

    splunkd refuses ``time_window`` on anything else. It decides from what it
    knows about the input rather than from the values, so rows generated by
    ``makeresults`` are refused there even though their times do not fall —
    the one corner of this option mockdr does not imitate.
    """
    stamps = [_as_float(r.get("_time")) for r in rows]
    if any(s is None for s in stamps):
        return False
    ordered = [s for s in stamps if s is not None]
    return ordered == sorted(ordered) or ordered == sorted(ordered, reverse=True)


def _cmd_streamstats(rows: Rows, command: SPLCommand) -> Rows:
    aggs, by_fields, options = _aggregation_plan(
        command.arg, options=_STREAMSTATS_OPTIONS,
    )
    if not aggs:
        aggs = [("count", "", "count")]
    window = int(options.get("window", "0") or 0)
    current = _reads_as_true(options.get("current", "true"))
    reset_on_change = _reads_as_true(options.get("reset_on_change", "false"))
    reset_before = parse_where(options["reset_before"]) if (
        "reset_before" in options
    ) else None
    reset_after = parse_where(options["reset_after"]) if (
        "reset_after" in options
    ) else None

    span = _duration_seconds(options["time_window"]) if (
        "time_window" in options
    ) else 0.0
    if span and not _time_ordered(rows):
        msg = (
            "time_window can only be used on input that is sorted in time "
            "order (both ascending and descending order are ok)."
        )
        raise ValueError(msg)

    seen: dict[tuple, Rows] = {}
    previous: tuple | None = None
    out: Rows = []
    for row in rows:
        if any(row.get(f) in (None, "") for f in by_fields):
            # A row that does not carry every by-field belongs to no group,
            # and splunkd adds nothing to it at all.
            out.append(dict(row))
            continue
        key = tuple(str(row.get(f, "")) for f in by_fields)
        if reset_on_change and previous is not None and key != previous:
            seen.pop(key, None)
        previous = key
        if reset_before is not None and evaluate(reset_before, row):
            seen.pop(key, None)

        members = seen.setdefault(key, [])
        # `current=f` reports the rows before this one; the row still joins
        # the window for the rows that follow.
        pool = [*members, row] if current else list(members)
        members.append(row)
        if window:
            pool = pool[-window:]
            del members[:-window]
        if span:
            # The far edge is open: with events an hour apart, a one-hour
            # window holds only the event itself (measured).
            edge = (_as_float(row.get("_time")) or 0.0) - span
            pool = [r for r in pool if (_as_float(r.get("_time")) or 0.0) > edge]

        computed = dict(row)
        computed.update(_aggregated(aggs, pool))
        out.append(computed)

        if reset_after is not None and evaluate(reset_after, row):
            seen.pop(key, None)
    return out


# ---------------------------------------------------------------------------
# makeresults
#
# The command every Splunk example and every hand-written test starts with.
# mockdr did not know it and refused the whole search, so the standard way to
# try an expression could not be tried against the mock at all.
#
# splunkd words its refusals here under three different subjects — the option
# values under `SearchProcessor`, the inline-data rules under
# `MakeResultsProcessor`, and the placement rule under the command itself —
# and one of them carries no subject at all. All measured against 10.4.2.
# ---------------------------------------------------------------------------

#: `key=value`, with a quoted value kept whole: `data="a,b\n1,2"`.
_OPTION_RE = re.compile(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|\S*)')

#: splunkd takes these four words for true and these four for false, and
#: refuses `on`, `y` and everything else (measured).
_TRUE_WORDS = frozenset({"true", "t", "yes", "1"})
_FALSE_WORDS = frozenset({"false", "f", "no", "0"})

#: A non-negative integer as splunkd reads it: `+2` and `02` pass, `1.5`,
#: `-1` and ` 2 ` do not.
_COUNT_RE = re.compile(r"\+?\d+")

_INLINE_PAIR = (
    "You must specify both 'format' and 'data' arguments for 'makeresults' "
    "to read inline data. If you are providing inline data, specify both "
    "'format' and 'data'. If you are not providing inline data, do not "
    "specify either argument."
)
_INLINE_ONLY = (
    "When 'makeresults' generates events from inline data, it does not allow "
    "arguments other than 'format' and 'data'. If you are providing inline "
    "data for 'makeresults', specify only the 'format' and 'data' arguments."
)
_INLINE_JSON = (
    "Incorrectly-formatted JSON data detected. Make sure your JSON-formatted "
    "data starts with '[' and ends with ']' and consists of JSON objects."
)


class OptionError(ValueError):
    """A failure splunkd words under a subject of its own.

    Most command failures read "Error in '<command>' command: ...", but the
    option checks are done by the search processor and say so, and one of the
    inline-data messages carries no subject at all. A client keying on the
    message reads the whole line, so the subject is part of the answer.
    """

    def __init__(self, message: str, *, subject: str = "SearchProcessor") -> None:
        """Record the message and the subject splunkd blames for it."""
        super().__init__(message)
        self.subject = subject


def _options(arg: str) -> dict[str, str]:
    """The command's ``key=value`` options, refusing a repeated one."""
    found: dict[str, str] = {}
    for match in _OPTION_RE.finditer(arg):
        name = match.group(1).lower()
        if name in found:
            msg = f"Option '{name}' should not be specified more than once."
            raise OptionError(msg)
        value = match.group(2)
        if value.startswith('"') and value.endswith('"') and len(value) > 1:
            value = value[1:-1].replace('\\"', '"')
        found[name] = value
    return found


def _option_error(name: str, expected: str, raw: str) -> OptionError:
    return OptionError(
        f"Invalid option value. Expecting a '{expected}' for option "
        f"'{name}'. Instead got '{raw}'.",
    )


def _boolean_option(name: str, raw: str) -> bool:
    word = raw.lower()
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    raise _option_error(name, "boolean", raw)


def _reads_as_true(raw: str) -> bool:
    """A boolean option that is not checked, only read."""
    return raw.lower() in _TRUE_WORDS


def _inline_rows(options: dict[str, str]) -> Rows:
    """The rows ``format=`` and ``data=`` describe.

    ``csv`` reads a header line and the rows under it, and carries no
    ``_time`` at all; ``json`` takes an array of objects and gives each row
    the object's text as ``_raw`` alongside its fields.
    """
    if set(options) - {"format", "data"}:
        raise OptionError(_INLINE_ONLY, subject="MakeResultsProcessor")
    fmt = options["format"].lower()
    data = options["data"]
    if fmt == "csv":
        return _inline_csv(data)
    if fmt == "json":
        return _inline_json(data)
    raise OptionError(
        f"An invalid 'format' was specified: {options['format']}. "
        "Valid 'format' options are 'csv' and 'json'.",
        subject="MakeResultsProcessor",
    )


def _inline_csv(data: str) -> Rows:
    """Inline CSV: the first line names the fields, the rest are rows."""
    lines = list(csv.reader(io.StringIO(data)))
    if len(lines) < 2:
        return []
    header = lines[0]
    # A row with fewer cells than the header simply lacks those fields, and
    # cells beyond the header are dropped (both measured).
    return [
        {
            name: cell
            for name, cell in zip(header, row, strict=False)
            # An empty cell is a field the row does not have: `count(v)`
            # does not count it (measured).
            if cell != ""
        }
        for row in lines[1:]
    ]


def _inline_json(data: str) -> Rows:
    """Inline JSON: an array of objects, each row keeping its own text."""
    try:
        document = json.loads(data)
    except ValueError:
        # Text that is not JSON at all produces no rows and no complaint.
        return []
    if not isinstance(document, list) or any(
        not isinstance(item, dict) for item in document
    ):
        raise OptionError(_INLINE_JSON, subject="")
    now = float(int(current_time()))
    rows: Rows = []
    for item in document:
        row: dict[str, Any] = {
            "_raw": json.dumps(item, separators=(",", ":")),
            "_time": now,
        }
        for key, value in item.items():
            row[key] = (
                json.dumps(value, separators=(",", ":"))
                if isinstance(value, (dict, list))
                else value
            )
        rows.append(row)
    return rows


def _cmd_makeresults(_rows: Rows, command: SPLCommand) -> Rows:
    """Generate rows out of nothing, the way ``| makeresults`` does.

    Each row carries ``_time`` and nothing else; ``count`` asks for more of
    them, ``annotate=true`` adds the server that made them, and ``format``
    with ``data`` reads rows from inline text instead.
    """
    options = _options(command.arg)
    if "format" in options or "data" in options:
        if "format" not in options or "data" not in options:
            raise OptionError(_INLINE_PAIR, subject="MakeResultsProcessor")
        return _inline_rows(options)

    raw_count = options.get("count", "1")
    if not _COUNT_RE.fullmatch(raw_count):
        raise _option_error("count", "non-negative integer", raw_count)
    # Whole seconds: splunkd's own row reads `...:02.000+00:00`, never a
    # fraction of a second.
    row: dict[str, Any] = {"_time": float(int(current_time()))}
    if "annotate" in options and _boolean_option("annotate", options["annotate"]):
        row["splunk_server"] = SPLUNK_SERVER
    return [dict(row) for _ in range(int(raw_count))]


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
            value = evaluate(node, updated, mode="eval")
            if isinstance(value, bool):
                # splunkd refuses to store one, and says what to do instead.
                raise SPLExprError(_BOOLEAN_ASSIGNMENT)
            if value is None:
                # An expression with no value leaves the field out of the row
                # rather than setting it empty — `mvindex` past the end and a
                # `strptime` that did not parse both land here.
                updated.pop(name, None)
                continue
            updated[name] = value
        out.append(updated)
    return out


#: What splunkd answers when an eval would store a boolean (measured on
#: 10.4.2). mockdr stored it, so a client saw a field where production sees a
#: failed search.
_BOOLEAN_ASSIGNMENT = (
    "Fields cannot be assigned a boolean result. "
    "Instead, try if([bool expr], [expr], [expr])."
)


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
    # An alias stops at a comma: `stats perc50(n) as p, avg(n)` names the
    # first statistic `p`, not `p,`.
    r"(?P<func>\w+)\s*\(\s*(?P<field>[^)]*)\s*\)(?:\s+as\s+(?P<alias>[^\s,]+))?"
    r"|(?P<bare>\bcount\b)(?:\s+as\s+(?P<bare_alias>[^\s,]+))?",
    re.IGNORECASE,
)


def _cmd_stats(rows: Rows, command: SPLCommand) -> Rows:
    aggs, by_fields, _options = _aggregation_plan(command.arg)
    if not aggs:
        aggs = [("count", "", "count")]

    if not by_fields:
        # One row over everything, even when there is nothing: `stats count`
        # on an empty result set is a row saying 0. It is written only if
        # something in it could be computed.
        whole: dict[str, Any] = _aggregated(aggs, rows)
        return [whole] if whole else []

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
        record: dict[str, Any] = dict(zip(by_fields, key, strict=False))
        record.update(_aggregated(aggs, groups[key]))
        out.append(record)
    return out


def _aggregated(
    aggs: list[tuple[str, str, str]], members: Rows,
) -> dict[str, Any]:
    """The aggregations that have a value over *members*, by their alias."""
    record: dict[str, Any] = {}
    for func, field, alias in aggs:
        value = _aggregate(func, field, members)
        if value is not _ABSENT:
            record[alias] = value
    return record


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
    agg_text, by_fields = split_by(command.arg)
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
                computed = _aggregate(aggs[0][0], aggs[0][1], subset)
                if computed is not _ABSENT:
                    record[value] = computed
        else:
            record.update(_aggregated(aggs, members))
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


#: What an aggregation with nothing to compute produces. splunkd does not
#: write the field at all: `stats sum(text_field)` gives a row without it,
#: and a `stats` with no `by` and nothing to show gives no row. The mock
#: wrote 0 and "", so a client reading `sum(bytes)` got a number here and no
#: field in production — the difference a mock exists to prevent.
_ABSENT = object()


def _present(field: str, rows: Rows) -> list[Any]:
    """The values the rows carry for *field*, empty strings included.

    A field a row does not have takes no part; a field it has as "" does,
    which is what `count(x)` counts and `values(x)` shows (measured).
    """
    return [r[field] for r in rows if r.get(field) is not None]


def _median(numbers: list[float]) -> float:
    """The middle value, and what splunkd does when there are two of them.

    It averages the pair and rounds an exact half *up*: the median of 1 and 2
    is 2 there, of 1 and 4 is 3, and of 1.2 and 1.4 is 1.3 — the rounding
    only appears when the average lands on a half. `perc50` interpolates
    without it, which is why the two disagree on an even number of values.
    """
    ordered = sorted(numbers)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    middle = (ordered[mid - 1] + ordered[mid]) / 2
    return middle + 0.5 if middle % 1 == 0.5 else middle


def _aggregate(func: str, field: str, rows: Rows) -> Any:
    name = func.lower()
    if name in ("count", "c"):
        return len(rows) if not field else len(_present(field, rows))
    if name in ("dc", "distinct_count"):
        return len({str(v) for v in _present(field, rows)})

    values = _present(field, rows)
    if not values and name in ("values", "list"):
        return _ABSENT
    if name == "values":
        return sorted({str(v) for v in values})
    if name == "list":
        return [str(v) for v in values]
    if name in ("first", "last"):
        if not values:
            return _ABSENT
        return values[0] if name == "first" else values[-1]

    if name in ("earliest", "latest"):
        # By event time, not pipeline order — which is what separates these
        # from `first` and `last`.
        timed = [r for r in rows if r.get(field) is not None]
        if not timed:
            return _ABSENT
        by_time = sorted(timed, key=lambda r: _as_float(r.get("_time")) or 0.0)
        return by_time[0 if name == "earliest" else -1].get(field)

    if name == "mode":
        if not values:
            return _ABSENT
        counts = Counter(str(v) for v in values)
        best = max(counts.values())
        return sorted(v for v, c in counts.items() if c == best)[0]

    numbers = [n for n in (_as_float(v) for v in values) if n is not None]
    if name in ("min", "max"):
        if numbers:
            # A number wins over text: over 1, "a" and 3, `max` is 3.
            return _shrink(min(numbers) if name == "min" else max(numbers))
        if not values:
            return _ABSENT
        texts = sorted(str(v) for v in values)
        return texts[0] if name == "min" else texts[-1]

    if not numbers:
        # Every arithmetic statistic needs a number to work from.
        return _ABSENT
    if name in _SPREAD_FUNCTIONS:
        return _SPREAD_FUNCTIONS[name](numbers)
    percentile = _PERCENTILE_RE.fullmatch(name)
    if percentile:
        # `perc95(x)` matches the first group and `p95(x)` the second.
        return _percentile(numbers, float(percentile.group(1) or percentile.group(2)))
    if name == "sum":
        return _shrink(sum(numbers))
    if name in ("avg", "mean"):
        return _shrink(sum(numbers) / len(numbers))
    if name == "range":
        return _shrink(max(numbers) - min(numbers))
    if name == "median":
        return _shrink(_median(numbers))
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


#: The statistics `_aggregate` computes. Anything else is refused by name,
#: the way splunkd refuses it, rather than raising out of the handler.
_KNOWN_AGGREGATIONS = frozenset({
    "count", "c", "dc", "distinct_count", "values", "list", "first", "last",
    "earliest", "latest", "mode", "min", "max", "sum", "avg", "mean",
    "range", "median", *_SPREAD_FUNCTIONS,
})


def _invalid_argument(text: str) -> ValueError:
    """The word splunkd uses for a token a stats-like command cannot read."""
    return ValueError(f"The argument '{text}' is invalid.")


def _known_aggregation(name: str) -> bool:
    """Whether ``name`` is a statistic, ``perc95`` and ``p95`` included."""
    lowered = name.lower()
    return lowered in _KNOWN_AGGREGATIONS or bool(
        _PERCENTILE_RE.fullmatch(lowered),
    )


def _aggregation_plan(
    arg: str, *, options: frozenset[str] = frozenset(),
) -> tuple[list[tuple[str, str, str]], list[str], dict[str, str]]:
    """Read a stats-like argument into aggregations, by-fields and options.

    Whatever is left over is something splunkd would not have understood, and
    it refuses the command rather than running the part it did read:
    ``stats count nosucharg=1`` is an error there and was ignored here.
    """
    found: dict[str, str] = {}
    def take_option(match: re.Match[str]) -> str:
        found[match.group(1).lower()] = match.group(2).strip('"')
        return " "

    if options:
        pattern = r"\b(" + "|".join(sorted(options)) + r")\s*=\s*(\"[^\"]*\"|\S+)"
        arg = re.sub(pattern, take_option, arg, flags=re.IGNORECASE)
    agg_text, by_fields = split_by(arg)

    aggs: list[tuple[str, str, str]] = []
    remainder = agg_text
    for match in _AGG_RE.finditer(agg_text):
        func = (match.group("func") or match.group("bare") or "").lower()
        if not _known_aggregation(func):
            raise _invalid_argument(match.group(0))
        remainder = remainder.replace(match.group(0), " ", 1)
    aggs = _parse_aggregations(agg_text)

    leftover = [token for token in re.split(r"[,\s]+", remainder) if token]
    if leftover:
        raise _invalid_argument(leftover[0])
    return aggs, by_fields, found


def aggregation_aliases(arg: str) -> list[str]:
    """The column names a stats-like argument declares, in the order given.

    splunkd lists a column it declared even when no row carries a value for
    it: `stats sum(text_field) by host` names `sum(text_field)` in the
    response's field block and writes it in no row.
    """
    agg_text, _by_fields = split_by(arg)
    return [alias for _func, _field, alias in _parse_aggregations(agg_text)]


def split_by(arg: str) -> tuple[str, list[str]]:
    """Split a command argument into its aggregations and its ``by`` fields."""
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
    "makeresults": _cmd_makeresults,
    "streamstats": _cmd_streamstats,
    "tail": _cmd_tail,
    "timechart": _cmd_timechart,
    "top": _cmd_top,
    "where": _cmd_where,
}
