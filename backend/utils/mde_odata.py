"""OData v4 ``$filter`` parser and filter engine for Microsoft Defender API.

Implements the subset of OData filter syntax used by the XSOAR MDE
integration:

- ``eq``, ``ne`` — equality / inequality
- ``gt``, ``ge``, ``lt``, ``le`` — range comparisons
- ``contains(field,'value')`` — substring match
- ``startswith(field,'value')`` — prefix match
- ``endswith(field,'value')`` — suffix match
- ``and``, ``or`` — logical conjunction, with ``and`` binding tighter
- Parenthetical grouping
- Single-quoted string literals (``''`` escapes a quote), unquoted numbers
  and unquoted ISO-8601 date/time literals

Anything outside that subset — ``not``, ``in``, nested function calls,
arithmetic — raises :class:`ODataFilterError`, which the app maps to the
``400`` the real APIs return.  Nothing is skipped silently: ignoring input
would widen the filter and hand back more records than were asked for.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from utils.nested import get_nested


class ODataFilterError(ValueError):
    """Raised when a ``$filter`` expression cannot be parsed.

    The real Defender and Graph APIs answer a malformed or unsupported
    ``$filter`` with ``400``, so this is translated into a vendor-shaped bad
    request rather than surfacing as a ``500``.  It subclasses ``ValueError``
    so existing ``except ValueError`` callers keep working.
    """


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ODataClause:
    """A single comparison in an OData filter expression.

    Attributes:
        field:    Target field name (e.g. ``"severity"``).
        operator: One of ``eq``, ``ne``, ``gt``, ``ge``, ``lt``, ``le``,
                  ``contains``, ``startswith``, ``endswith``.
        value:    Comparison value (always stored as string).
        literal:  How *value* was written — ``"bool"`` and ``"null"`` are
                  compared against real ``bool``/``None`` fields rather than
                  their ``str()`` forms, so ``enabled eq true`` matches while
                  ``enabled eq 'true'`` stays a string comparison.
    """

    field: str
    operator: str
    value: str
    literal: str = "string"


@dataclass
class ODataGroup:
    """A boolean combination of nested filter nodes.

    OData binds ``and`` tighter than ``or``, and parentheses override both.
    Neither can be represented by a flat clause list, so the parser builds a
    tree instead.

    Attributes:
        operator: ``"and"`` or ``"or"``.
        children: Operands, evaluated left to right.
    """

    operator: str
    children: list[ODataNode]


#: Either a leaf comparison or a boolean group of further nodes.
ODataNode = ODataClause | ODataGroup


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"(?P<func>contains|startswith|endswith)\s*\("
    r"|(?P<paren>[()])"
    # A doubled quote is OData's escape for a literal one, so it must not end
    # the token: 'O''Brien' is one string, not 'O' followed by junk.
    r"|(?P<string>'(?:[^']|'')*')"
    r"|(?P<op>eq|ne|ge|gt|le|lt)\b"
    r"|(?P<conj>and|or)\b"
    # Unquoted keyword literals. Must precede `word`, which would otherwise
    # swallow them and compare "true" against str(True) == "True" — never
    # equal, so `eq true` matched nothing and `ne true` matched everything.
    r"|(?P<bool>true|false)\b"
    r"|(?P<null>null)\b"
    # Edm.Guid literals are unquoted in OData v4. Must precede `word` and
    # `number`, either of which would bite off a prefix and leave rubble.
    r"|(?P<guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
    # OData v4 writes date/time literals unquoted, and they must be lexed
    # whole — otherwise "2026-08-08T00:00:00Z" degrades into the number 2026
    # followed by rubble, and the comparison silently comes out coarser than
    # the caller asked for. Must precede `number` for the same reason.
    r"|(?P<datetime>\d{4}-\d{2}-\d{2}"
    r"(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?)"
    r"|(?P<word>[A-Za-z_][A-Za-z0-9_./]*)"
    r"|(?P<number>-?\d+(?:\.\d+)?)"
    r"|(?P<comma>,)"
    r"|\s+",
    re.IGNORECASE,
)


def _tokenise(text: str) -> list[tuple[str, str]]:
    """Tokenise an OData ``$filter`` string.

    Returns:
        List of ``(type, value)`` token tuples.

    Raises:
        ODataFilterError: If any character cannot be lexed. Skipping them
            would widen the filter rather than narrow it — a junk-only
            expression would lex to nothing and match every record, and an
            unterminated quote would silently drop its opening quote.
    """
    tokens: list[tuple[str, str]] = []
    pos = 0
    for m in _TOKEN_RE.finditer(text):
        if m.start() > pos:
            msg = f"unexpected character(s) in filter: {text[pos:m.start()]!r}"
            raise ODataFilterError(msg)
        pos = m.end()

        if m.group("func"):
            tokens.append(("FUNC", m.group("func").lower()))
        elif m.group("paren"):
            tokens.append(("PAREN", m.group("paren")))
        elif m.group("string"):
            # Strip surrounding quotes, then unescape doubled quotes
            tokens.append(("STRING", m.group("string")[1:-1].replace("''", "'")))
        elif m.group("op"):
            tokens.append(("OP", m.group("op").lower()))
        elif m.group("conj"):
            tokens.append(("CONJ", m.group("conj").lower()))
        elif m.group("bool"):
            tokens.append(("BOOL", m.group("bool").lower()))
        elif m.group("null"):
            tokens.append(("NULL", "null"))
        elif m.group("guid"):
            tokens.append(("GUID", m.group("guid")))
        elif m.group("datetime"):
            tokens.append(("DATETIME", m.group("datetime")))
        elif m.group("word"):
            tokens.append(("WORD", m.group("word")))
        elif m.group("number"):
            tokens.append(("NUMBER", m.group("number")))
        elif m.group("comma"):
            tokens.append(("COMMA", ","))
        # whitespace is silently skipped

    if pos < len(text):
        msg = f"unexpected character(s) in filter: {text[pos:]!r}"
        raise ODataFilterError(msg)
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    """Recursive-descent parser for OData ``$filter`` expressions."""

    #: Deepest parenthesis nesting accepted. Guards the recursive descent —
    #: a RecursionError is not an ODataFilterError, so it would escape the
    #: handler as a 500. No real caller nests anywhere near this far.
    MAX_DEPTH = 50

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.depth = 0

    def _peek(self) -> tuple[str, str] | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _advance(self) -> tuple[str, str]:
        if self.pos >= len(self.tokens):
            msg = "unexpected end of filter expression"
            raise ODataFilterError(msg)
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _expect(self, kind: str) -> str:
        tok = self._advance()
        if tok[0] != kind:
            msg = f"expected {kind}, got {tok[1]!r}"
            raise ODataFilterError(msg)
        return tok[1]

    def _expect_exact(self, kind: str, value: str) -> str:
        """Require a specific token, not merely one of the right kind.

        ``_expect("PAREN")`` would happily accept ``(`` where ``)`` belongs,
        so ``contains(name,'a'(`` parsed clean.
        """
        tok = self._advance()
        if tok != (kind, value):
            msg = f"expected {value!r}, got {tok[1]!r}"
            raise ODataFilterError(msg)
        return tok[1]

    def parse(self) -> ODataNode | None:
        """Parse the full filter expression into a node tree.

        Returns:
            Root node, or ``None`` when the expression is empty.

        Raises:
            ODataFilterError: If the expression is malformed, or if anything
                is left over after the root node. Ignoring a trailing tail
                would silently *widen* the filter — dropping ``and n gt 3``
                returns more records than the caller asked for, which is far
                worse than refusing the query.
        """
        node = self._parse_or()
        if self.pos < len(self.tokens):
            leftover = " ".join(tok[1] for tok in self.tokens[self.pos:])
            msg = f"unparsed trailing input: {leftover!r}"
            raise ODataFilterError(msg)
        return node

    def _parse_or(self) -> ODataNode | None:
        """Parse ``and``-groups joined by ``or`` — the loosest binding."""
        return self._parse_binary("or", self._parse_and)

    def _parse_and(self) -> ODataNode | None:
        """Parse atoms joined by ``and``, which binds tighter than ``or``."""
        return self._parse_binary("and", self._parse_atom)

    def _parse_binary(
        self,
        conjunction: str,
        parse_operand: Callable[[], ODataNode | None],
    ) -> ODataNode | None:
        """Parse ``operand (<conjunction> operand)*`` at one precedence level.

        Raises:
            ODataFilterError: If a conjunction has no right-hand operand.
                Dropping it would leave ``x eq '1' and`` meaning ``x eq '1'``,
                the same silent widening the trailing-input check rejects.
        """
        children: list[ODataNode] = []
        first = parse_operand()
        if first is not None:
            children.append(first)

        while True:
            tok = self._peek()
            if tok is None or tok[0] != "CONJ" or tok[1] != conjunction:
                break
            self._advance()
            operand = parse_operand()
            if operand is None:
                msg = f"{conjunction!r} has no right-hand operand"
                raise ODataFilterError(msg)
            children.append(operand)

        if not children:
            return None
        if len(children) == 1:
            return children[0]
        return ODataGroup(operator=conjunction, children=children)

    def _parse_atom(self) -> ODataNode | None:
        """Parse a single comparison or parenthesised group."""
        tok = self._peek()
        if tok is None:
            return None

        # Parenthesised group
        if tok == ("PAREN", "("):
            if self.depth >= self.MAX_DEPTH:
                msg = f"filter nested deeper than {self.MAX_DEPTH} levels"
                raise ODataFilterError(msg)
            self._advance()  # consume '('
            self.depth += 1
            try:
                inner = self._parse_or()
            finally:
                self.depth -= 1
            if inner is None:
                msg = "empty parentheses in filter"
                raise ODataFilterError(msg)
            self._expect_exact("PAREN", ")")
            return inner

        # Function call: contains/startswith/endswith(field, 'value').
        # The tokeniser's `func` pattern matches the trailing "(" too, so the
        # opening paren is already consumed by the time we get here.
        if tok[0] == "FUNC":
            func_name = self._advance()[1]
            field_name = self._expect("WORD")
            self._expect("COMMA")
            value, literal = self._expect_value()
            self._expect_exact("PAREN", ")")
            return ODataClause(
                field=field_name, operator=func_name, value=value, literal=literal,
            )

        # Standard comparison: field op value
        if tok[0] == "WORD":
            field_name = self._advance()[1]
            op = self._expect("OP")
            value, literal = self._expect_value()
            return ODataClause(
                field=field_name, operator=op, value=value, literal=literal,
            )

        msg = f"unexpected token: {tok[1]!r}"
        raise ODataFilterError(msg)

    #: Token kinds usable as an operand, mapped to the literal kind recorded
    #: on the clause. Only bool/null need non-string comparison.
    _VALUE_TOKENS = {  # noqa: RUF012
        "STRING": "string",
        "WORD": "string",
        "NUMBER": "string",
        "DATETIME": "string",
        "GUID": "string",
        "BOOL": "bool",
        "NULL": "null",
    }

    def _expect_value(self) -> tuple[str, str]:
        """Consume a literal operand, rejecting anything that isn't one.

        Accepting whatever came next used to swallow the closing paren, so
        ``contains(name,)`` silently compared against ``")"``.

        Returns:
            ``(value, literal_kind)``.
        """
        tok = self._peek()
        if tok is None or tok[0] not in self._VALUE_TOKENS:
            found = tok[1] if tok else "end of expression"
            msg = f"expected a value, got {found!r}"
            raise ODataFilterError(msg)
        kind = self._VALUE_TOKENS[tok[0]]
        return self._advance()[1], kind


# ---------------------------------------------------------------------------
# Public API — parsing
# ---------------------------------------------------------------------------

def parse_odata_filter(filter_str: str) -> ODataNode | None:
    """Parse an OData ``$filter`` string into a node tree.

    Args:
        filter_str: OData filter expression, e.g.
                    ``"severity eq 'High' and status ne 'Resolved'"``.

    Returns:
        Root :class:`ODataClause` or :class:`ODataGroup`, or ``None`` when the
        filter is empty or contains nothing parseable.
    """
    if not filter_str or not filter_str.strip():
        return None
    tokens = _tokenise(filter_str)
    parser = _Parser(tokens)
    return parser.parse()


# ---------------------------------------------------------------------------
# Public API — filtering
# ---------------------------------------------------------------------------

def _get_nested(record: dict, path: str) -> Any:
    """Traverse a dict using a dot-separated or slash-separated key path.

    Args:
        record: The dict to traverse.
        path:   Key path, e.g. ``"device.hostname"`` or ``"device/hostname"``.

    Returns:
        The value at the path, or ``None`` if any segment is missing.
    """
    return get_nested(record, path.replace("/", "."))


def _match_keyword_literal(field_val: Any, clause: ODataClause) -> bool:
    """Compare a field against an unquoted ``true``/``false``/``null``.

    Args:
        field_val: Value from the record.
        clause:    Clause whose ``literal`` is ``"bool"`` or ``"null"``.

    Returns:
        ``True`` if the record matches. Only ``eq``/``ne`` are meaningful
        against these literals; any other operator never matches.
    """
    if clause.operator not in ("eq", "ne"):
        return False

    if clause.literal == "null":
        equal = field_val is None
    else:
        # A string field holding "true" should still satisfy `eq true`, which
        # is how these records come back from the JSON seeders.
        expected = clause.value == "true"
        if isinstance(field_val, bool):
            equal = field_val is expected
        elif isinstance(field_val, str) and field_val.lower() in ("true", "false"):
            equal = (field_val.lower() == "true") is expected
        else:
            equal = False

    return equal if clause.operator == "eq" else not equal


def _match_clause(record: dict, clause: ODataClause) -> bool:
    """Test whether a single record satisfies one OData clause.

    Args:
        record: Dict record to test.
        clause: Parsed OData clause.

    Returns:
        ``True`` if the record matches.
    """
    field_val = _get_nested(record, clause.field)
    field_str = str(field_val) if field_val is not None else ""
    target = clause.value

    # Unquoted keyword literals compare against the real value, not its str()
    # form — str(True) is "True", which never equals the "true" the caller
    # wrote, so `eq true` matched nothing and `ne true` matched everything.
    if clause.literal in ("bool", "null"):
        return _match_keyword_literal(field_val, clause)

    # A collection-valued field matches when any member matches, which is what
    # a lambda like `assignedLicenses/any(l: l/skuId eq '…')` asks.
    if isinstance(field_val, (list, tuple)):
        members = [str(v) for v in field_val]
        if clause.operator == "eq":
            return any(m == target for m in members)
        if clause.operator == "ne":
            return all(m != target for m in members)
        return any(
            _match_clause({clause.field: m}, clause) for m in members
        )

    if clause.operator == "eq":
        return field_str == target

    if clause.operator == "ne":
        return field_str != target

    if clause.operator == "contains":
        return target.lower() in field_str.lower()

    if clause.operator == "startswith":
        return field_str.lower().startswith(target.lower())

    if clause.operator == "endswith":
        return field_str.lower().endswith(target.lower())

    # Range operators — try numeric, fall back to string
    if clause.operator in ("gt", "ge", "lt", "le"):
        return _compare_range(field_val, target, clause.operator)

    return False


def _match_node(record: dict, node: ODataNode) -> bool:
    """Test a record against a filter node, honouring ``and``/``or`` nesting.

    Args:
        record: Dict record to test.
        node:   Parsed filter node.

    Returns:
        ``True`` if the record matches.
    """
    if isinstance(node, ODataGroup):
        if node.operator == "or":
            return any(_match_node(record, child) for child in node.children)
        return all(_match_node(record, child) for child in node.children)
    return _match_clause(record, node)


def _compare_range(field_val: Any, target: str, op: str) -> bool:
    """Compare a field value against a target using a range operator.

    Args:
        field_val: Value from the record.
        target:    Target value string.
        op:        One of ``gt``, ``ge``, ``lt``, ``le``.

    Returns:
        ``True`` if the comparison holds.
    """
    if field_val is None:
        return False
    try:
        fv = float(str(field_val))
        tv = float(target)
        if op == "gt":
            return fv > tv
        if op == "ge":
            return fv >= tv
        if op == "lt":
            return fv < tv
        return fv <= tv
    except (ValueError, TypeError):
        pass
    # Fall back to lexicographic (handles ISO timestamps)
    fs = str(field_val)
    if op == "gt":
        return fs > target
    if op == "ge":
        return fs >= target
    if op == "lt":
        return fs < target
    return fs <= target


def apply_odata_filter(records: list[dict], filter_str: str) -> list[dict]:
    """Apply an OData ``$filter`` expression to a list of records.

    Args:
        records:    List of dicts to filter.
        filter_str: OData filter string.

    Returns:
        Filtered subset matching all conditions.
    """
    root = parse_odata_filter(filter_str)
    if root is None:
        return list(records)
    return [record for record in records if _match_node(record, root)]


def apply_odata_orderby(
    records: list[dict],
    orderby: str | None,
    enums: Mapping[str, Sequence[str]] | None = None,
) -> list[dict]:
    """Sort records according to an OData ``$orderby`` expression.

    Args:
        records: List of dicts to sort.
        orderby: OData orderby string, e.g. ``"alertCreationTime desc"``.
        enums:   Field name -> that field's members in the order the vendor
                 declares them. OData orders an enum by its declared position
                 and not alphabetically, so without this
                 ``$orderby=severity desc`` answers `Medium` first where the
                 product answers `High` — a triage client asking for the worst
                 alerts got the wrong ones, with a 200.

    Returns:
        Sorted list.
    """
    if not orderby or not orderby.strip():
        return records

    ordered = list(records)
    # OData allows several keys; a flat `r.get(name)` also missed every nested
    # path, so `$orderby=properties/title` sorted nothing while reporting
    # success. Least-significant key first so the leading key wins.
    for clause in reversed([c.strip() for c in orderby.split(",") if c.strip()]):
        parts = clause.split()
        field_name = parts[0]
        desc = len(parts) > 1 and parts[1].lower() == "desc"
        members = (enums or {}).get(field_name.rsplit("/", 1)[-1])
        ordered.sort(key=_orderby_key(field_name, members), reverse=desc)
    return ordered


def _orderby_key(
    field_name: str, members: Sequence[str] | None = None,
) -> Callable[[dict], tuple[int, float, str]]:
    """Build a sort key that reads dotted paths and orders numbers numerically.

    An enum-typed field is ordered by where its value sits in the declared
    list; a value outside it sorts after every declared one, which is where
    an unrecognised member belongs.
    """
    positions = {member: index for index, member in enumerate(members or [])}

    def key(record: dict) -> tuple[int, float, str]:
        value = _get_nested(record, field_name)
        if value is None or value == "":
            return (2, 0.0, "")
        if positions:
            return (0, float(positions.get(str(value), len(positions))), "")
        try:
            return (0, float(value), "")
        except (TypeError, ValueError):
            return (1, 0.0, str(value))
    return key


def apply_odata_select(records: list[dict], select: str | None) -> list[dict]:
    """Filter record fields according to an OData ``$select`` expression.

    Args:
        records: List of dicts.
        select:  Comma-separated field names, or ``None`` for all fields.

    Returns:
        List of dicts with only the selected fields.
    """
    if not select or not select.strip():
        return records
    fields = {f.strip() for f in select.split(",")}
    return [{k: v for k, v in r.items() if k in fields} for r in records]
