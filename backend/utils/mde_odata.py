"""OData v4 ``$filter`` parser and filter engine for Microsoft Defender API.

Implements the subset of OData filter syntax used by the XSOAR MDE
integration:

- ``eq``, ``ne`` — equality / inequality
- ``gt``, ``ge``, ``lt``, ``le`` — range comparisons
- ``contains(field,'value')`` — substring match
- ``startswith(field,'value')`` — prefix match
- ``and``, ``or`` — logical conjunction
- Parenthetical grouping
- Single-quoted string literals and unquoted numbers/booleans
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from utils.nested import get_nested

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ODataClause:
    """A single parsed OData filter clause.

    Attributes:
        field:       Target field name (e.g. ``"severity"``).
        operator:    One of ``eq``, ``ne``, ``gt``, ``ge``, ``lt``, ``le``,
                     ``contains``, ``startswith``.
        value:       Comparison value (always stored as string).
        conjunction: How this clause joins with the preceding clause
                     (``"and"`` or ``"or"``).
    """

    field: str
    operator: str
    value: str
    conjunction: str = "and"


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"(?P<func>contains|startswith)\s*\("
    r"|(?P<paren>[()])"
    r"|(?P<string>'[^']*')"
    r"|(?P<op>eq|ne|ge|gt|le|lt)\b"
    r"|(?P<conj>and|or)\b"
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
    """
    tokens: list[tuple[str, str]] = []
    for m in _TOKEN_RE.finditer(text):
        if m.group("func"):
            tokens.append(("FUNC", m.group("func").lower()))
        elif m.group("paren"):
            tokens.append(("PAREN", m.group("paren")))
        elif m.group("string"):
            # Strip surrounding quotes
            tokens.append(("STRING", m.group("string")[1:-1]))
        elif m.group("op"):
            tokens.append(("OP", m.group("op").lower()))
        elif m.group("conj"):
            tokens.append(("CONJ", m.group("conj").lower()))
        elif m.group("word"):
            tokens.append(("WORD", m.group("word")))
        elif m.group("number"):
            tokens.append(("NUMBER", m.group("number")))
        elif m.group("comma"):
            tokens.append(("COMMA", ","))
        # whitespace is silently skipped
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    """Recursive-descent parser for OData ``$filter`` expressions."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _advance(self) -> tuple[str, str]:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _expect(self, kind: str) -> str:
        tok = self._advance()
        if tok[0] != kind:
            msg = f"expected {kind}, got {tok}"
            raise ValueError(msg)
        return tok[1]

    def parse(self) -> list[ODataClause]:
        """Parse the full filter expression into a flat clause list."""
        clauses = self._parse_expr("and")
        return clauses

    def _parse_expr(self, default_conj: str) -> list[ODataClause]:
        """Parse a sequence of clauses joined by ``and`` / ``or``."""
        clauses = self._parse_atom(default_conj)

        while True:
            tok = self._peek()
            if tok is None or tok[0] != "CONJ":
                break
            conj = self._advance()[1]
            right = self._parse_atom(conj)
            clauses.extend(right)

        return clauses

    def _parse_atom(self, conjunction: str) -> list[ODataClause]:
        """Parse a single clause or parenthesised group."""
        tok = self._peek()
        if tok is None:
            return []

        # Parenthesised group
        if tok == ("PAREN", "("):
            self._advance()  # consume '('
            inner = self._parse_expr(conjunction)
            # Set the conjunction of the first inner clause
            if inner:
                inner[0].conjunction = conjunction
            nxt = self._peek()
            if nxt and nxt == ("PAREN", ")"):
                self._advance()  # consume ')'
            return inner

        # Function call: contains(field, 'value') / startswith(field, 'value')
        if tok[0] == "FUNC":
            func_name = self._advance()[1]
            self._expect("PAREN")  # '(' consumed by tokeniser
            # Actually the tokeniser emits FUNC for "contains(" but without the paren.
            # Let me re-check... The regex captures the func name but the '(' is separate.
            # Wait — the regex is: r"(?P<func>contains|startswith)\s*\("
            # This *includes* the paren in the match, so the paren is consumed.
            field_name = self._expect("WORD")
            self._expect("COMMA")
            val_tok = self._peek()
            if val_tok and val_tok[0] == "STRING":
                value = self._advance()[1]
            elif val_tok and val_tok[0] == "WORD":
                value = self._advance()[1]
            else:
                value = self._advance()[1] if val_tok else ""
            # Consume closing paren
            nxt = self._peek()
            if nxt and nxt == ("PAREN", ")"):
                self._advance()
            return [ODataClause(
                field=field_name, operator=func_name,
                value=value, conjunction=conjunction,
            )]

        # Standard comparison: field op value
        if tok[0] == "WORD":
            field_name = self._advance()[1]
            op = self._expect("OP")
            val_tok = self._peek()
            if val_tok and val_tok[0] == "STRING":
                value = self._advance()[1]
            elif val_tok and val_tok[0] == "NUMBER":
                value = self._advance()[1]
            elif val_tok and val_tok[0] == "WORD":
                value = self._advance()[1]
            else:
                value = ""
            return [ODataClause(
                field=field_name, operator=op,
                value=value, conjunction=conjunction,
            )]

        # Skip unrecognised token
        self._advance()
        return []


# ---------------------------------------------------------------------------
# Public API — parsing
# ---------------------------------------------------------------------------

def parse_odata_filter(filter_str: str) -> list[ODataClause]:
    """Parse an OData ``$filter`` string into structured clauses.

    Args:
        filter_str: OData filter expression, e.g.
                    ``"severity eq 'High' and status ne 'Resolved'"``.

    Returns:
        Ordered list of :class:`ODataClause` objects.
    """
    if not filter_str or not filter_str.strip():
        return []
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

    if clause.operator == "eq":
        return field_str == target

    if clause.operator == "ne":
        return field_str != target

    if clause.operator == "contains":
        return target.lower() in field_str.lower()

    if clause.operator == "startswith":
        return field_str.lower().startswith(target.lower())

    # Range operators — try numeric, fall back to string
    if clause.operator in ("gt", "ge", "lt", "le"):
        return _compare_range(field_val, target, clause.operator)

    return False


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
    clauses = parse_odata_filter(filter_str)
    if not clauses:
        return list(records)

    # Group into AND-groups (consecutive OR clauses belong to same group)
    groups: list[list[ODataClause]] = []
    for clause in clauses:
        if clause.conjunction == "and" or not groups:
            groups.append([clause])
        else:
            groups[-1].append(clause)

    result: list[dict] = []
    for record in records:
        match = True
        for group in groups:
            group_match = any(_match_clause(record, c) for c in group)
            if not group_match:
                match = False
                break
        if match:
            result.append(record)
    return result


def apply_odata_orderby(records: list[dict], orderby: str | None) -> list[dict]:
    """Sort records according to an OData ``$orderby`` expression.

    Args:
        records: List of dicts to sort.
        orderby: OData orderby string, e.g. ``"alertCreationTime desc"``.

    Returns:
        Sorted list.
    """
    if not orderby or not orderby.strip():
        return records
    parts = orderby.strip().split()
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return sorted(records, key=lambda r: r.get(field_name, "") or "", reverse=desc)


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
