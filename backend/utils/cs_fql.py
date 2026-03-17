"""CrowdStrike Falcon Query Language (FQL) parser and filter engine.

FQL is used by CrowdStrike APIs for record filtering.  This module
implements the subset required by SOAR integrations:

- ``+`` between terms = AND
- ``,`` between same-field terms = OR
- ``:`` equals, ``:!`` not-equals
- ``:>=``, ``:<=``, ``:>``, ``:<`` range operators
- ``'*pattern*'`` wildcard (fnmatch)
- ``['val1','val2']`` in-list
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from fnmatch import fnmatch
from typing import Any

from utils.nested import get_nested as _get_nested

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FqlClause:
    """A single parsed FQL filter clause.

    Attributes:
        field:       Field name the clause targets, e.g. ``"hostname"``.
        operator:    One of ``"eq"``, ``"neq"``, ``"gte"``, ``"lte"``,
                     ``"gt"``, ``"lt"``, ``"in"``, ``"wildcard"``.
        values:      List of values for the clause (single-element for
                     scalar operators, multi-element for ``"in"`` / ``"or"``).
        conjunction: How this clause joins with the preceding clause —
                     ``"and"`` or ``"or"``.
    """

    field: str
    operator: str
    values: list[str] = dc_field(default_factory=list)
    conjunction: str = "and"


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Matches a single FQL term: field, operator, value(s).
# Groups: 1=field, 2=operator chars (e.g. ":!", ":>="), 3=value portion.
_TERM_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.]*)"   # field name
    r":(!=?|>=?|<=?|!>|!<|)"       # operator (may be empty = plain equals)
    r"(.+)"                         # value portion (quoted, bracketed, or bare)
)

_QUOTED_RE = re.compile(r"^'(.*)'$")
_BRACKET_RE = re.compile(r"^\[(.+)\]$")
_BRACKET_ITEM_RE = re.compile(r"'([^']*)'")


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------

def _classify_operator(op_chars: str, value: str) -> str:
    """Map raw operator characters and value shape to a canonical operator name.

    Args:
        op_chars: Raw operator string after the ``:``, e.g. ``"!"``, ``">="``.
        value:    The raw value portion (needed to detect wildcards and lists).

    Returns:
        Canonical operator string.
    """
    if _BRACKET_RE.match(value):
        return "in"
    if op_chars == "!" or op_chars == "!=":
        return "neq"
    if op_chars == ">=":
        return "gte"
    if op_chars == "<=":
        return "lte"
    if op_chars == ">":
        return "gt"
    if op_chars == "<":
        return "lt"
    # Plain equals — but check for wildcards in the value.
    unquoted = _unquote(value)
    if "*" in unquoted or "?" in unquoted:
        return "wildcard"
    return "eq"


def _unquote(value: str) -> str:
    """Strip surrounding single quotes from a value string.

    Args:
        value: Possibly quoted string.

    Returns:
        Unquoted string.
    """
    m = _QUOTED_RE.match(value)
    return m.group(1) if m else value


def _extract_values(value_portion: str, operator: str) -> list[str]:
    """Extract the list of values from a raw FQL value portion.

    Args:
        value_portion: Raw value string (may be quoted, bracketed, or bare).
        operator:      Canonical operator name (determines parse strategy).

    Returns:
        List of unquoted value strings.
    """
    if operator == "in":
        m = _BRACKET_RE.match(value_portion)
        if m:
            return [item.group(1) for item in _BRACKET_ITEM_RE.finditer(m.group(1))]
        return [_unquote(value_portion)]
    return [_unquote(value_portion)]


def _parse_term(raw: str) -> FqlClause | None:
    """Parse a single FQL term string into an ``FqlClause``.

    Args:
        raw: A single term like ``hostname:'*server*'`` or ``severity:>=50``.

    Returns:
        Parsed clause, or ``None`` if the term is unparseable.
    """
    m = _TERM_RE.match(raw.strip())
    if not m:
        return None
    fld = m.group(1)
    op_chars = m.group(2)
    value_portion = m.group(3)
    operator = _classify_operator(op_chars, value_portion)
    values = _extract_values(value_portion, operator)
    return FqlClause(field=fld, operator=operator, values=values)


# ---------------------------------------------------------------------------
# Public API — parsing
# ---------------------------------------------------------------------------

def _smart_split(text: str, delimiter: str) -> list[str]:
    """Split *text* on *delimiter*, respecting single-quotes and brackets.

    Delimiters inside ``'...'`` or ``[...]`` are treated as literal
    characters and do not trigger a split.

    Args:
        text:      The string to split.
        delimiter: Single character to split on.

    Returns:
        List of substrings.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    in_bracket = False

    for ch in text:
        if ch == "'" and not in_bracket:
            in_quote = not in_quote
            current.append(ch)
        elif ch == "[" and not in_quote:
            in_bracket = True
            current.append(ch)
        elif ch == "]" and not in_quote:
            in_bracket = False
            current.append(ch)
        elif ch == delimiter and not in_quote and not in_bracket:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)

    parts.append("".join(current))
    return parts


def parse_fql(fql: str) -> list[FqlClause]:
    """Parse an FQL string into structured clauses.

    Handles AND (``+``) and OR (``,`` between same-field terms) conjunctions.

    Args:
        fql: FQL filter string, e.g.
             ``"hostname:'*server*'+status:'normal'"``.

    Returns:
        Ordered list of ``FqlClause`` objects representing the filter.
    """
    if not fql or not fql.strip():
        return []

    clauses: list[FqlClause] = []

    # Split on '+' for AND groups first (respecting quotes/brackets).
    and_groups = _smart_split(fql, "+")

    for group in and_groups:
        # Within a group, ',' separates OR terms on the same field.
        or_terms = _smart_split(group, ",")

        if len(or_terms) == 1:
            clause = _parse_term(or_terms[0])
            if clause:
                clause.conjunction = "and"
                clauses.append(clause)
        else:
            # Multiple comma-separated terms → OR group.
            for i, term in enumerate(or_terms):
                clause = _parse_term(term)
                if clause:
                    clause.conjunction = "or" if i > 0 else "and"
                    clauses.append(clause)

    return clauses


# ---------------------------------------------------------------------------
# Public API — filtering
# ---------------------------------------------------------------------------

def _match_clause(record: dict, clause: FqlClause) -> bool:
    """Test whether a single record satisfies one FQL clause.

    Args:
        record: Dict record to test.
        clause: Parsed FQL clause.

    Returns:
        ``True`` if the record matches the clause.
    """
    field_val = _get_nested(record, clause.field)
    field_str = str(field_val) if field_val is not None else ""

    if clause.operator == "eq":
        return any(field_str == v for v in clause.values)

    if clause.operator == "neq":
        return all(field_str != v for v in clause.values)

    if clause.operator == "wildcard":
        return any(fnmatch(field_str, v) for v in clause.values)

    if clause.operator == "in":
        return field_str in clause.values

    # Range operators — attempt numeric comparison first, fall back to string.
    if clause.operator in ("gte", "lte", "gt", "lt"):
        for v in clause.values:
            if not _compare_range(field_val, v, clause.operator):
                return False
        return True

    return False


def _compare_range(field_val: Any, target: str, op: str) -> bool:
    """Compare a field value against a target using a range operator.

    Attempts numeric comparison first; falls back to lexicographic string
    comparison.

    Args:
        field_val: Value from the record.
        target:    Target value from the FQL clause.
        op:        One of ``"gte"``, ``"lte"``, ``"gt"``, ``"lt"``.

    Returns:
        ``True`` if the comparison holds.
    """
    if field_val is None:
        return False

    # Try numeric comparison.
    try:
        fv = float(str(field_val))
        tv = float(target)
        if op == "gte":
            return fv >= tv
        if op == "lte":
            return fv <= tv
        if op == "gt":
            return fv > tv
        return fv < tv
    except (ValueError, TypeError):
        pass

    # Fall back to string comparison (handles ISO timestamps).
    fs = str(field_val)
    if op == "gte":
        return fs >= target
    if op == "lte":
        return fs <= target
    if op == "gt":
        return fs > target
    return fs < target


def apply_fql(records: list[dict], fql: str) -> list[dict]:
    """Apply a CrowdStrike FQL filter string to a list of records.

    Args:
        records: List of dicts to filter.
        fql:     FQL filter string, e.g.
                 ``"hostname:'*server*'+status:'normal'"``.

    Returns:
        Filtered subset matching all FQL conditions.
    """
    clauses = parse_fql(fql)
    if not clauses:
        return list(records)

    # Group clauses into AND-groups.  Consecutive OR clauses belong to the
    # preceding AND-group.
    groups: list[list[FqlClause]] = []
    for clause in clauses:
        if clause.conjunction == "and" or not groups:
            groups.append([clause])
        else:
            groups[-1].append(clause)

    result: list[dict] = []
    for record in records:
        match = True
        for group in groups:
            # Within a group, ANY clause matching = group passes (OR semantics).
            group_match = any(_match_clause(record, c) for c in group)
            if not group_match:
                match = False
                break
        if match:
            result.append(record)

    return result
