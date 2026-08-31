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

This is NOT a full KQL engine — and what it cannot read, it refuses.

Everything it did not recognise used to be dropped on the floor: an unknown
pipeline operator, and any `where` predicate outside a handful of shapes.
`| where SourceSystem contains 'zzzzz'` answered all 210 rows, every one of
them looking to the client like a match, and `| distinct SourceSystem`
answered the whole table. Log Analytics answers a query it cannot compile
with 400, so an unreadable clause raises `UnsupportedKqlError` and the route
says so, rather than returning rows that mean something else.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


class UnsupportedKqlError(ValueError):
    """A query this parser cannot evaluate, refused rather than half-read.

    Half-reading is the dangerous option: a dropped predicate widens the
    result instead of narrowing it, so the client is handed more rows than
    it asked for with nothing to say they do not match.
    """


@dataclass
class KQLQuery:
    """Parsed KQL query components."""

    tables: list[str] = field(default_factory=list)
    where_clauses: list[tuple[str, str, str]] = field(default_factory=list)  # (field, op, value)
    where_in_clauses: list[tuple[str, list[str]]] = field(default_factory=list)
    where_not_in_clauses: list[tuple[str, list[str]]] = field(default_factory=list)
    #: `| distinct a, b` — the columns to reduce to, in the order named.
    distinct_fields: list[str] = field(default_factory=list)
    #: `| count` — one row, one column, the number of rows reaching it.
    count_only: bool = False
    #: The first thing in the query this parser could not read, if any.
    #: Recorded rather than raised so the caller can resolve the table
    #: first: "there is no such table" is the more fundamental answer, and
    #: it is the one a client can act on.
    unsupported: str = ""
    project_fields: list[str] = field(default_factory=list)
    sort_field: str = ""
    sort_descending: bool = True
    take: int = 0
    summarize_func: str = ""
    summarize_by: str = ""
    #: The field an aggregate without a `by` is taken over.
    summarize_field: str = ""
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
        elif cmd_lower.startswith("distinct "):
            try:
                result.distinct_fields = [
                    _column(f) for f in cmd[9:].split(",") if f.strip()
                ]
            except UnsupportedKqlError as exc:
                if not result.unsupported:
                    result.unsupported = str(exc)
        elif cmd_lower == "count":
            result.count_only = True
        elif not result.unsupported:
            result.unsupported = (
                f"'{cmd.split(None, 1)[0]}' operator is not supported")


#: A column name as KQL lets it be written: bare, or bracket-quoted when it
#: carries a dot — `['event.Severity']` is how a client reaches into the
#: CrowdStrike table, whose columns are all dotted.
_COLUMN = r"(?:\[\s*['\"](?P<quoted>[^'\"]+)['\"]\s*\]|(?P<bare>\w+))"


def _column(text: str) -> str:
    """The column `text` names, with any bracket quoting removed."""
    match = re.fullmatch(r"\s*" + _COLUMN + r"\s*", text)
    if not match:
        msg = f"cannot read the column name {text.strip()!r}"
        raise UnsupportedKqlError(msg)
    return match.group("quoted") or match.group("bare")


#: The string operators, and how each is spelled negated.
_STRING_OPS: tuple[str, ...] = (
    "contains", "!contains", "startswith", "!startswith",
    "endswith", "!endswith", "has", "!has",
)


#: Raised out of the splitter, which has no `result` to record onto; the
#: caller turns it back into a recorded reason.
_OR_UNSUPPORTED = "'or' in a where clause is not supported"


def _split_top_level_and(clause: str) -> list[str]:
    """`a == 1 and b == 2` as its two parts, ignoring quoted text.

    `or` is deliberately absent: the executor applies clauses one after the
    other, which is an `and`, and quietly treating an `or` as one would widen
    or narrow the result with nothing to show for it.
    """
    parts: list[str] = []
    depth = 0
    quote = ""
    current: list[str] = []
    index = 0
    while index < len(clause):
        char = clause[index]
        if quote:
            if char == quote:
                quote = ""
            current.append(char)
        elif char in "\"'":
            quote = char
            current.append(char)
        elif char in "([":
            depth += 1
            current.append(char)
        elif char in ")]":
            depth -= 1
            current.append(char)
        elif depth == 0 and clause[index:index + 5].lower() == " and ":
            parts.append("".join(current))
            current = []
            index += 5
            continue
        elif depth == 0 and clause[index:index + 4].lower() == " or ":
            raise UnsupportedKqlError(_OR_UNSUPPORTED)
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _parse_where(clause: str, result: KQLQuery) -> None:
    """Parse a where clause, recording what it cannot read."""
    try:
        parts = _split_top_level_and(clause)
    except UnsupportedKqlError as exc:
        if not result.unsupported:
            result.unsupported = str(exc)
        return
    for part in parts:
        _parse_one_predicate(part, result)


def _parse_one_predicate(clause: str, result: KQLQuery) -> None:
    """Parse a single comparison, with no `and` left in it."""
    clause = clause.strip()

    # Handle: field in ("val1", "val2"), and its negation
    in_match = re.fullmatch(
        _COLUMN + r"\s+(?P<negated>!?)in\s*~?\s*\(\s*(?P<values>.*?)\s*\)",
        clause, re.IGNORECASE | re.DOTALL,
    )
    if in_match:
        field_name = in_match.group("quoted") or in_match.group("bare")
        values = [
            v.strip().strip('"').strip("'")
            for v in in_match.group("values").split(",") if v.strip()
        ]
        if in_match.group("negated"):
            result.where_not_in_clauses.append((field_name, values))
        else:
            result.where_in_clauses.append((field_name, values))
        return

    # Handle: field > ago(24h)
    ago_match = re.fullmatch(
        _COLUMN + r"\s*>\s*ago\((\d+)([smhd])\)",
        clause, re.IGNORECASE,
    )
    if ago_match:
        field_name = ago_match.group("quoted") or ago_match.group("bare")
        amount = int(ago_match.group(3))
        unit = ago_match.group(4)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        threshold = time.time() - (amount * multipliers.get(unit, 1))
        result.ago_filters.append((field_name, threshold))
        return

    # Handle the string operators: contains, startswith, endswith, has, and
    # each one's `!` spelling.  Every one of these used to fall through and
    # be dropped, so the predicate widened the result to the whole table.
    ops = "|".join(re.escape(op) for op in sorted(_STRING_OPS, key=len, reverse=True))
    text_match = re.fullmatch(
        _COLUMN + rf"\s+(?P<op>{ops})\s*~?\s*(?P<value>.+)",
        clause, re.IGNORECASE | re.DOTALL,
    )
    if text_match:
        result.where_clauses.append((
            text_match.group("quoted") or text_match.group("bare"),
            text_match.group("op").lower(),
            text_match.group("value").strip().strip('"').strip("'"),
        ))
        return

    # Handle: field == "value" or field == value or field != "value"
    eq_match = re.fullmatch(
        _COLUMN + r'\s*(?P<op>==|!=|>=|<=|=~|!~|>|<)\s*(?P<value>.+)',
        clause, re.IGNORECASE | re.DOTALL,
    )
    if eq_match:
        result.where_clauses.append((
            eq_match.group("quoted") or eq_match.group("bare"),
            eq_match.group("op"),
            eq_match.group("value").strip().strip('"').strip("'"),
        ))
        return

    if not result.unsupported:
        result.unsupported = f"cannot read the where clause {clause!r}"


def _parse_sort(cmd: str, result: KQLQuery) -> None:
    """Parse sort/order by clause."""
    match = re.match(r'(?:sort|order)\s+by\s+(\w+)(?:\s+(asc|desc))?', cmd, re.IGNORECASE)
    if match:
        result.sort_field = match.group(1)
        result.sort_descending = (match.group(2) or "desc").lower() == "desc"


def _parse_summarize(clause: str, result: KQLQuery) -> None:
    """Parse a summarize clause.

    `count() by <field>` and `max(<field>)` — the second because every data
    connector this workspace publishes hands the client
    `<Table>_CL | summarize max(TimeGenerated)` as the query that tells it
    when data last arrived, and an unparsed summarize answered the whole
    table instead of one row.
    """
    counted = re.match(r'count\(\)\s+by\s+(\w+)', clause.strip(), re.IGNORECASE)
    if counted:
        result.summarize_func = "count"
        result.summarize_by = counted.group(1)
        return
    aggregated = re.match(
        r'(max|min)\(\s*(\w+)\s*\)\s*$', clause.strip(), re.IGNORECASE)
    if aggregated:
        result.summarize_func = aggregated.group(1).lower()
        result.summarize_field = aggregated.group(2)


def _parse_extend(clause: str, result: KQLQuery) -> None:
    """Parse extend clause: field = expression."""
    match = re.match(r'(\w+)\s*=\s*(.*)', clause.strip())
    if match:
        result.extend_fields[match.group(1)] = match.group(2)
