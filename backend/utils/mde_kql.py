"""A working subset of KQL for Advanced Hunting.

``Query`` was accepted and never evaluated: every request returned the same
three synthetic rows, so a hunting query naming a table that does not exist, or
carrying a ``where`` that excludes everything, still came back with results. A
detection engineer testing a query against mockdr learned nothing about it.

Supported: ``Table | where … | project … | project-away … | extend … |
summarize … by … | order by … | take/limit N | distinct … | count``, with the
comparison and string operators hunting queries actually use (``==``, ``!=``,
``>``, ``>=``, ``<``, ``<=``, ``contains``, ``!contains``, ``startswith``,
``endswith``, ``has``, ``in``, ``!in``, ``matches regex``), combined with
``and`` / ``or`` / ``not`` and parentheses.

Anything outside that subset raises :class:`KqlError` so the caller can answer
a 400, the way Defender does, rather than returning rows that were never asked
for.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["KqlError", "KqlQuery", "evaluate_kql", "parse_kql"]

Row = dict[str, Any]


class KqlError(ValueError):
    """Raised when a query cannot be parsed or names something unknown."""


@dataclass
class KqlQuery:
    """A parsed hunting query: a source table and an ordered operator list."""

    table: str
    operators: list[tuple[str, str]]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_OPERATORS = frozenset({
    "where", "project", "project-away", "extend", "summarize", "order",
    "sort", "take", "limit", "distinct", "count", "top",
})


def _split_pipeline(text: str) -> list[str]:
    """Split on ``|`` outside quotes and parentheses."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth = max(depth - 1, 0)
        elif char == "|" and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_kql(query: str) -> KqlQuery:
    """Parse a hunting query into its table and operator chain.

    Raises:
        KqlError: If the query is empty or an operator is not supported.
    """
    text = re.sub(r"//[^\n]*", " ", query or "").strip()
    if not text:
        msg = "A recognized query is expected"
        raise KqlError(msg)

    segments = _split_pipeline(text)
    table = segments[0].strip()
    if not re.fullmatch(r"[A-Za-z_][\w]*", table):
        msg = f"A recognized table name is expected, found '{table}'"
        raise KqlError(msg)

    operators: list[tuple[str, str]] = []
    for segment in segments[1:]:
        name, _, argument = segment.partition(" ")
        name = name.strip().lower()
        if name == "order" or name == "sort":
            argument = re.sub(r"^\s*by\s+", "", argument, flags=re.IGNORECASE)
            name = "order"
        if name not in _OPERATORS:
            msg = f"The operator '{name}' is not supported"
            raise KqlError(msg)
        operators.append((name, argument.strip()))
    return KqlQuery(table=table, operators=operators)


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<number>-?\d+\.\d+|-?\d+)
  | (?P<op>==|!=|<=|>=|=~|!~|<|>|\(|\)|,)
  | (?P<word>[^\s()=<>!,]+)
    """,
    re.VERBOSE,
)

_STRING_OPS = {
    "contains", "!contains", "startswith", "!startswith", "endswith",
    "!endswith", "has", "!has", "in", "!in", "matches",
}


@dataclass
class _Token:
    kind: str
    text: str


def _tokenize(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    while pos < len(source):
        match = _TOKEN_RE.match(source, pos)
        if match is None:
            msg = f"Unexpected character at offset {pos}"
            raise KqlError(msg)
        pos = match.end()
        if match.lastgroup != "ws":
            tokens.append(_Token(match.lastgroup or "", match.group()))
    return tokens


class _PredicateParser:
    """Builds a row predicate from a ``where`` expression."""

    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> _Token | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> _Token:
        token = self._peek()
        if token is None:
            msg = "Unexpected end of expression"
            raise KqlError(msg)
        self._pos += 1
        return token

    def _accept(self, text: str) -> bool:
        token = self._peek()
        if token is not None and token.text.lower() == text:
            self._pos += 1
            return True
        return False

    def parse(self) -> Callable[[Row], bool]:
        """Parse the whole expression."""
        predicate = self._parse_or()
        if self._peek() is not None:
            msg = f"Unexpected input near '{self._peek().text}'"  # type: ignore[union-attr]
            raise KqlError(msg)
        return predicate

    def _parse_or(self) -> Callable[[Row], bool]:
        left = self._parse_and()
        while self._accept("or"):
            right = self._parse_and()
            left = (lambda a, b: lambda row: a(row) or b(row))(left, right)
        return left

    def _parse_and(self) -> Callable[[Row], bool]:
        left = self._parse_not()
        while self._accept("and"):
            right = self._parse_not()
            left = (lambda a, b: lambda row: a(row) and b(row))(left, right)
        return left

    def _parse_not(self) -> Callable[[Row], bool]:
        if self._accept("not"):
            inner = self._parse_not()
            return lambda row: not inner(row)
        return self._parse_comparison()

    def _parse_comparison(self) -> Callable[[Row], bool]:
        if self._accept("("):
            inner = self._parse_or()
            if not self._accept(")"):
                msg = "Expected ')'"
                raise KqlError(msg)
            return inner

        left = self.parse_operand()
        token = self._peek()
        if token is None:
            # A bare term is truthiness on that column.
            return lambda row: bool(left(row))

        operator = token.text.lower()
        if token.kind == "op" and operator in ("==", "!=", "<", "<=", ">", ">=", "=~", "!~"):
            self._next()
            right = self.parse_operand()
            return _comparison(operator, left, right)
        if operator in _STRING_OPS:
            self._next()
            if operator == "matches":
                self._accept("regex")
            right = self.parse_operand()
            return _string_op(operator, left, right)
        return lambda row: bool(left(row))

    def parse_operand(self) -> Callable[[Row], Any]:
        """Parse one operand — a literal, a value list, or a column."""
        token = self._next()
        if token.kind == "string":
            literal = token.text[1:-1]
            return lambda _row: literal
        if token.kind == "number":
            number = float(token.text) if "." in token.text else int(token.text)
            return lambda _row: number
        if token.text == "(":
            # A value list, as in `X in ("a","b")`.
            values: list[Any] = []
            while not self._accept(")"):
                item = self._next()
                if item.text == ",":
                    continue
                if item.kind == "string":
                    values.append(item.text[1:-1])
                elif item.kind == "number":
                    values.append(
                        float(item.text) if "." in item.text else int(item.text),
                    )
                else:
                    values.append(item.text)
            return lambda _row: values
        column = token.text
        return lambda row: row.get(column)


def _numeric(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _comparison(
    operator: str,
    left: Callable[[Row], Any],
    right: Callable[[Row], Any],
) -> Callable[[Row], bool]:
    def predicate(row: Row) -> bool:
        a, b = left(row), right(row)
        if operator == "==":
            return _equal(a, b)
        if operator == "!=":
            return not _equal(a, b)
        if operator == "=~":
            return str(a).lower() == str(b).lower()
        if operator == "!~":
            return str(a).lower() != str(b).lower()
        # Ordering against a missing value is false, as in KQL.
        if a is None or b is None:
            return False
        an, bn = _numeric(a), _numeric(b)
        if an is None or bn is None:
            an_s, bn_s = str(a), str(b)
            return _order(operator, an_s, bn_s)
        return _order(operator, an, bn)

    return predicate


def _order(operator: str, a: Any, b: Any) -> bool:
    if operator == "<":
        return bool(a < b)
    if operator == "<=":
        return bool(a <= b)
    if operator == ">":
        return bool(a > b)
    return bool(a >= b)


def _equal(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    an, bn = _numeric(a), _numeric(b)
    if an is not None and bn is not None:
        return an == bn
    return str(a) == str(b)


def _string_op(
    operator: str,
    left: Callable[[Row], Any],
    right: Callable[[Row], Any],
) -> Callable[[Row], bool]:
    negated = operator.startswith("!")
    base = operator.lstrip("!")

    def predicate(row: Row) -> bool:
        value = left(row)
        target = right(row)
        text = "" if value is None else str(value).lower()

        if base == "in":
            candidates = target if isinstance(target, list) else [target]
            result = any(str(c).lower() == text for c in candidates)
        elif base == "contains":
            result = str(target).lower() in text
        elif base == "startswith":
            result = text.startswith(str(target).lower())
        elif base == "endswith":
            result = text.endswith(str(target).lower())
        elif base == "has":
            result = str(target).lower() in re.split(r"[^0-9a-z_]+", text)
        elif base == "matches":
            result = bool(re.search(str(target), str(value or "")))
        else:  # pragma: no cover - guarded by _STRING_OPS
            msg = f"The operator '{operator}' is not supported"
            raise KqlError(msg)
        return not result if negated else result

    return predicate


# ---------------------------------------------------------------------------
# Operator execution
# ---------------------------------------------------------------------------

def evaluate_kql(rows: list[Row], query: KqlQuery) -> list[Row]:
    """Run *query*'s operators over *rows*, in order.

    Raises:
        KqlError: On an operator argument that cannot be understood.
    """
    result = [dict(r) for r in rows]
    for name, argument in query.operators:
        result = _APPLY[name](result, argument)
    return result


def _op_where(rows: list[Row], argument: str) -> list[Row]:
    predicate = _PredicateParser(_tokenize(argument)).parse()
    return [r for r in rows if predicate(r)]


def _op_project(rows: list[Row], argument: str) -> list[Row]:
    columns = _columns(argument)
    return [{c: r.get(c) for c in columns} for r in rows]


def _op_project_away(rows: list[Row], argument: str) -> list[Row]:
    columns = set(_columns(argument))
    return [{k: v for k, v in r.items() if k not in columns} for r in rows]


def _op_extend(rows: list[Row], argument: str) -> list[Row]:
    out: list[Row] = []
    assignments = [a for a in _split_commas(argument) if "=" in a]
    for row in rows:
        updated = dict(row)
        for assignment in assignments:
            name, _, expression = assignment.partition("=")
            updated[name.strip()] = _evaluate_operand(expression.strip(), updated)
        out.append(updated)
    return out


def _evaluate_operand(expression: str, row: Row) -> Any:
    """Evaluate a single ``extend`` right-hand side against *row*."""
    parser = _PredicateParser(_tokenize(expression))
    return parser.parse_operand()(row)


def _op_summarize(rows: list[Row], argument: str) -> list[Row]:
    parts = re.split(r"(?i)\sby\s", argument, maxsplit=1)
    aggregation = parts[0]
    grouping = parts[1] if len(parts) > 1 else ""
    group_columns = _columns(grouping) if grouping else []

    aggregations = _parse_aggregations(aggregation)
    buckets: dict[tuple, list[Row]] = {}
    order: list[tuple] = []
    for row in rows:
        key = tuple(str(row.get(c, "")) for c in group_columns)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(row)

    out: list[Row] = []
    for key in order:
        members = buckets[key]
        record: Row = dict(zip(group_columns, key, strict=False))
        for alias, function, column in aggregations:
            record[alias] = _aggregate(function, column, members)
        out.append(record)
    return out


def _op_order(rows: list[Row], argument: str) -> list[Row]:
    ordered = list(rows)
    for clause in reversed(_split_commas(argument)):
        parts = clause.split()
        if not parts:
            continue
        column = parts[0]
        descending = len(parts) > 1 and parts[1].lower().startswith("desc")
        ordered.sort(key=_sorter(column), reverse=descending)
    return ordered


def _op_take(rows: list[Row], argument: str) -> list[Row]:
    match = re.search(r"\d+", argument)
    return rows[: int(match.group())] if match else rows


def _op_top(rows: list[Row], argument: str) -> list[Row]:
    match = re.match(r"\s*(\d+)\s*(?:by\s+(.*))?$", argument, re.IGNORECASE)
    if not match:
        msg = f"Cannot parse 'top {argument}'"
        raise KqlError(msg)
    limited = _op_order(rows, match.group(2)) if match.group(2) else rows
    return limited[: int(match.group(1))]


def _op_distinct(rows: list[Row], argument: str) -> list[Row]:
    columns = _columns(argument)
    seen: set[tuple] = set()
    out: list[Row] = []
    for row in rows:
        projected = {c: row.get(c) for c in columns} if columns else dict(row)
        key = tuple(str(v) for v in projected.values())
        if key not in seen:
            seen.add(key)
            out.append(projected)
    return out


def _op_count(rows: list[Row], _argument: str) -> list[Row]:
    return [{"Count": len(rows)}]


_APPLY: dict[str, Callable[[list[Row], str], list[Row]]] = {
    "where": _op_where,
    "project": _op_project,
    "project-away": _op_project_away,
    "extend": _op_extend,
    "summarize": _op_summarize,
    "order": _op_order,
    "take": _op_take,
    "limit": _op_take,
    "top": _op_top,
    "distinct": _op_distinct,
    "count": _op_count,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AGG_RE = re.compile(
    r"(?:(?P<alias>\w+)\s*=\s*)?(?P<func>\w+)\s*\(\s*(?P<column>[^)]*)\s*\)",
)


def _parse_aggregations(text: str) -> list[tuple[str, str, str]]:
    aggregations: list[tuple[str, str, str]] = []
    for match in _AGG_RE.finditer(text):
        function = match.group("func").lower()
        column = (match.group("column") or "").strip()
        default = f"{function}_{column}" if column else function
        aggregations.append((match.group("alias") or default, function, column))
    return aggregations or [("count_", "count", "")]


def _aggregate(function: str, column: str, rows: list[Row]) -> Any:
    if function == "count":
        return len(rows)
    if function == "dcount":
        return len({str(r.get(column)) for r in rows if r.get(column) is not None})
    if function == "make_set":
        return sorted({str(r.get(column)) for r in rows if r.get(column) is not None})
    if function == "make_list":
        return [r.get(column) for r in rows if r.get(column) is not None]
    if function in ("any", "take_any", "arg_max", "arg_min"):
        return rows[0].get(column) if rows else None

    numbers = [n for n in (_numeric(r.get(column)) for r in rows) if n is not None]
    if not numbers:
        return 0
    if function == "sum":
        return _shrink(sum(numbers))
    if function == "avg":
        return _shrink(sum(numbers) / len(numbers))
    if function == "min":
        return _shrink(min(numbers))
    if function == "max":
        return _shrink(max(numbers))
    msg = f"The aggregation function '{function}' is not supported"
    raise KqlError(msg)


def _columns(text: str) -> list[str]:
    return [c.strip() for c in _split_commas(text) if c.strip()]


def _split_commas(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _sorter(column: str) -> Callable[[Row], tuple[int, float, str]]:
    def key(row: Row) -> tuple[int, float, str]:
        value = row.get(column)
        if value is None:
            return (2, 0.0, "")
        number = _numeric(value)
        if number is not None:
            return (0, number, "")
        return (1, 0.0, str(value))
    return key


def _shrink(value: float) -> float | int:
    return int(value) if float(value).is_integer() else round(value, 6)
