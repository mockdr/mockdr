"""Elasticsearch query DSL interpreter for in-memory record filtering.

Implements the subset of Elasticsearch query DSL used by the XSOAR
Elasticsearch_v2 integration's ``es-search`` and ``es-eql-search`` commands.

Supported query types:
    - ``bool`` (must / should / must_not / filter)
    - ``match``, ``match_phrase``, ``match_all``
    - ``term``, ``terms``
    - ``range``
    - ``wildcard``
    - ``exists``
    - ``query_string`` (simple Lucene subset)

Also handles ``sort``, ``from`` (offset), and ``size`` (limit) from the
top-level search body.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from fnmatch import fnmatch
from typing import Any

from utils.nested import get_nested as _get_nested

_DEFAULT_SIZE = 10


class ESQueryError(ValueError):
    """Raised when a search body is not valid Elasticsearch query DSL.

    Elasticsearch answers a malformed or unknown query with a 400 carrying
    ``parsing_exception``; these previously escaped as bare ``ValueError`` and
    surfaced as a plain-text 500.
    """

# ---------------------------------------------------------------------------
# Range comparison helper
# ---------------------------------------------------------------------------

def _compare_range(field_val: Any, target: Any, op: str) -> bool:
    """Compare a field value against a target using a range operator.

    Attempts numeric comparison first; falls back to lexicographic string
    comparison (handles ISO timestamps).

    Args:
        field_val: Value from the record.
        target:    Target value from the query clause.
        op:        One of ``"gte"``, ``"lte"``, ``"gt"``, ``"lt"``.

    Returns:
        ``True`` if the comparison holds.
    """
    if field_val is None:
        return False

    # Try numeric comparison.
    try:
        fv = float(field_val)
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

    # Fall back to string comparison.
    fs = str(field_val)
    ts = str(target)
    if op == "gte":
        return fs >= ts
    if op == "lte":
        return fs <= ts
    if op == "gt":
        return fs > ts
    return fs < ts


# ---------------------------------------------------------------------------
# Predicate builders — one per query type
# ---------------------------------------------------------------------------

def _build_predicate(clause: dict) -> Callable[[dict], bool]:
    """Recursively build a predicate function from an ES query clause.

    Args:
        clause: A single Elasticsearch query clause dict.

    Returns:
        A callable that accepts a record dict and returns ``True`` on match.

    Raises:
        ValueError: If the clause contains an unsupported query type.
    """
    if not clause:
        return lambda _rec: True

    # Elasticsearch allows exactly one query type per clause object. Returning
    # on the first key silently discarded every later clause, so a body whose
    # second clause excluded everything still matched.
    if len(clause) > 1:
        extra = sorted(clause)[1]
        msg = f"[query] malformed query, expected [END_OBJECT] but found [{extra}]"
        raise ESQueryError(msg)

    for query_type, body in clause.items():
        builder = _BUILDERS.get(query_type)
        if builder is None:
            raise ESQueryError(f"no [query] registered for [{query_type}]")
        return builder(body)

    # Empty dict → match all.
    return lambda _rec: True


def _build_match_all(_body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``match_all``."""
    return lambda _rec: True


def _build_match(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``match``.

    Case-insensitive substring match.  If ``operator`` is ``"and"``, every
    word in the query must appear in the field value.
    """
    field, spec = next(iter(body.items()))
    if isinstance(spec, dict):
        query = str(spec.get("query", ""))
        operator = spec.get("operator", "or").lower()
    else:
        query = str(spec)
        operator = "or"

    query_lower = query.lower()
    words = query_lower.split()

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None:
            return False
        val_lower = str(val).lower()
        if operator == "and":
            return all(w in val_lower for w in words)
        return any(w in val_lower for w in words)

    return predicate


def _build_match_phrase(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``match_phrase``.

    Exact phrase match (case-insensitive).
    """
    field, query = next(iter(body.items()))
    phrase = str(query).lower()

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None:
            return False
        return phrase in str(val).lower()

    return predicate


def _build_term(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``term``.

    Exact (case-sensitive) value match.
    """
    field, spec = next(iter(body.items()))
    if isinstance(spec, dict):
        target = spec.get("value")
    else:
        target = spec

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None and target is None:
            return True
        if val is None or target is None:
            return False
        # Coerce both to same type for comparison.
        if isinstance(target, bool):
            return val is target or val == target
        if isinstance(target, (int, float)):
            try:
                return float(val) == float(target)
            except (ValueError, TypeError):
                return False
        return str(val) == str(target)

    return predicate


def _build_terms(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``terms``.

    Matches if the field value equals any of the listed values (case-sensitive).
    """
    field, values = next(iter(body.items()))
    str_values = {str(v) for v in values}

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None:
            return False
        return str(val) in str_values

    return predicate


def _build_range(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``range``."""
    field, bounds = next(iter(body.items()))

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        for op, target in bounds.items():
            if op in ("gte", "gt", "lte", "lt"):
                if not _compare_range(val, target, op):
                    return False
            # Ignore non-operator keys like "format", "time_zone".
        return True

    return predicate


def _build_wildcard(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``wildcard``.

    Uses ``fnmatch``-style matching (case-insensitive).
    """
    field, spec = next(iter(body.items()))
    if isinstance(spec, dict):
        pattern = str(spec.get("value", ""))
    else:
        pattern = str(spec)
    pattern_lower = pattern.lower()

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None:
            return False
        return fnmatch(str(val).lower(), pattern_lower)

    return predicate


def _build_exists(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``exists``."""
    field = body["field"]

    def predicate(rec: dict) -> bool:
        return _get_nested(rec, field) is not None

    return predicate


def _build_bool(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``bool`` query.

    Combines ``must``, ``filter``, ``should``, and ``must_not`` sub-clauses.
    """
    must_preds = [_build_predicate(c) for c in body.get("must", [])]
    filter_preds = [_build_predicate(c) for c in body.get("filter", [])]
    should_preds = [_build_predicate(c) for c in body.get("should", [])]
    must_not_preds = [_build_predicate(c) for c in body.get("must_not", [])]
    # Per ES: should clauses only carry a match requirement when there is no
    # must/filter to satisfy. Defaulting to 1 regardless meant adding a
    # non-matching should — which should affect scoring only — emptied the
    # result set.
    _default_min = 1 if (should_preds and not must_preds and not filter_preds) else 0
    min_should = body.get("minimum_should_match", _default_min)

    def predicate(rec: dict) -> bool:
        # must + filter: all must match.
        if not all(p(rec) for p in must_preds):
            return False
        if not all(p(rec) for p in filter_preds):
            return False
        # must_not: none may match.
        if any(p(rec) for p in must_not_preds):
            return False
        # should: at least min_should_match must match.
        if should_preds:
            matches = sum(1 for p in should_preds if p(rec))
            if matches < min_should:
                return False
        return True

    return predicate


# ---------------------------------------------------------------------------
# Query string (simple Lucene subset)
# ---------------------------------------------------------------------------

# Tokenises query_string into field:value pairs joined by AND/OR/NOT.
_QS_TOKEN_RE = re.compile(
    r"""
    \b(NOT)\b                        # NOT keyword
    | \b(AND)\b                      # AND keyword
    | \b(OR)\b                       # OR keyword
    | ([A-Za-z_][A-Za-z0-9_.]*):     # field name followed by colon
      (?:"([^"]*)"                   # quoted value
      |(\S+))                        # unquoted value
    | "([^"]*)"                      # bare quoted phrase (default field)
    | (\S+)                          # bare word (default field)
    """,
    re.VERBOSE,
)


def _build_query_string(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``query_string``.

    Supports a simple Lucene subset: ``field:value``, ``AND``, ``OR``,
    ``NOT``, and wildcards in values.
    """
    query = body.get("query", "")
    default_field = body.get("default_field", "_all")

    tokens = _qs_tokenise(query)
    predicate = _qs_parse_expr(tokens, 0, default_field)[0]
    return predicate


def _qs_tokenise(query: str) -> list[tuple[str, str, str]]:
    """Tokenise a query_string into ``(type, field, value)`` triples.

    Token types: ``"term"``, ``"AND"``, ``"OR"``, ``"NOT"``.
    """
    tokens: list[tuple[str, str, str]] = []
    for m in _QS_TOKEN_RE.finditer(query):
        if m.group(1):  # NOT
            tokens.append(("NOT", "", ""))
        elif m.group(2):  # AND
            tokens.append(("AND", "", ""))
        elif m.group(3):  # OR
            tokens.append(("OR", "", ""))
        elif m.group(4):  # field:value
            field = m.group(4)
            value = m.group(5) if m.group(5) is not None else m.group(6)
            tokens.append(("term", field, value))
        elif m.group(7) is not None:  # bare quoted phrase
            tokens.append(("term", "", m.group(7)))
        elif m.group(8):  # bare word
            tokens.append(("term", "", m.group(8)))
    return tokens


def _negate_pred(pred: Callable[[dict], bool]) -> Callable[[dict], bool]:
    """Return a predicate that is the logical negation of *pred*."""
    def negated(rec: dict) -> bool:
        return not pred(rec)
    return negated


def _qs_make_term_pred(
    field: str, value: str, default_field: str,
) -> Callable[[dict], bool]:
    """Build a predicate for a single query_string term."""
    has_wildcard = "*" in value or "?" in value

    def predicate(rec: dict) -> bool:
        if field:
            fv = _get_nested(rec, field)
            if fv is None:
                return False
            fv_str = str(fv).lower()
            val_lower = value.lower()
            if has_wildcard:
                return fnmatch(fv_str, val_lower)
            return val_lower in fv_str
        # No field specified — search all string values.
        val_lower = value.lower()
        return _search_all_values(rec, val_lower, has_wildcard)

    return predicate


def _search_all_values(record: dict, val_lower: str, wildcard: bool) -> bool:
    """Recursively search all string values in a record."""
    for v in record.values():
        if isinstance(v, dict):
            if _search_all_values(v, val_lower, wildcard):
                return True
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    if _search_all_values(item, val_lower, wildcard):
                        return True
                elif item is not None:
                    s = str(item).lower()
                    if wildcard and fnmatch(s, val_lower):
                        return True
                    if not wildcard and val_lower in s:
                        return True
        elif v is not None:
            s = str(v).lower()
            if wildcard and fnmatch(s, val_lower):
                return True
            if not wildcard and val_lower in s:
                return True
    return False


def _qs_parse_expr(
    tokens: list[tuple[str, str, str]],
    pos: int,
    default_field: str,
) -> tuple[Callable[[dict], bool], int]:
    """Parse a query_string expression with AND/OR/NOT precedence.

    Simple recursive descent: NOT binds tightest, then AND, then OR.
    Default conjunction between adjacent terms is AND.
    """
    predicates: list[Callable[[dict], bool]] = []
    conjunctions: list[str] = []  # "AND" or "OR" between predicates

    while pos < len(tokens):
        tok_type, field, value = tokens[pos]

        if tok_type == "NOT":
            pos += 1
            if pos >= len(tokens):
                break
            _, nf, nv = tokens[pos]
            inner = _qs_make_term_pred(nf, nv, default_field)
            predicates.append(_negate_pred(inner))
            pos += 1
        elif tok_type == "term":
            predicates.append(_qs_make_term_pred(field, value, default_field))
            pos += 1
        elif tok_type in ("AND", "OR"):
            conjunctions.append(tok_type)
            pos += 1
            continue
        else:
            pos += 1
            continue

        # If next token is not AND/OR, default to AND.
        if pos < len(tokens) and tokens[pos][0] == "term":
            conjunctions.append("AND")

    if not predicates:
        return (lambda _rec: True), pos

    # Combine: AND first, then OR.
    # Group consecutive AND-connected predicates.
    or_groups: list[list[Callable[[dict], bool]]] = [[predicates[0]]]
    for i, conj in enumerate(conjunctions):
        pred = predicates[i + 1] if i + 1 < len(predicates) else None
        if pred is None:
            break
        if conj == "OR":
            or_groups.append([pred])
        else:  # AND or default
            or_groups[-1].append(pred)

    def combined(rec: dict) -> bool:
        return any(
            all(p(rec) for p in group)
            for group in or_groups
        )

    return combined, pos


# ---------------------------------------------------------------------------
# Builder registry
# ---------------------------------------------------------------------------

_BUILDERS: dict[str, Callable[[dict], Callable[[dict], bool]]] = {
    "match_all": _build_match_all,
    "match": _build_match,
    "match_phrase": _build_match_phrase,
    "term": _build_term,
    "terms": _build_terms,
    "range": _build_range,
    "wildcard": _build_wildcard,
    "exists": _build_exists,
    "bool": _build_bool,
    "query_string": _build_query_string,
}


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def apply_es_sort(records: list[dict], sort_spec: list) -> list[dict]:
    """Apply an Elasticsearch sort specification to records.

    Args:
        records:   List of dicts to sort.
        sort_spec: Elasticsearch sort array, e.g.
                   ``[{"@timestamp": {"order": "desc"}}, "_score"]``.

    Returns:
        Sorted copy of the records list.
    """
    if not sort_spec:
        return list(records)

    # Parse sort spec into (field, reverse) pairs — applied in reverse order
    # so that the first sort key has highest priority.
    sort_keys: list[tuple[str, bool]] = []
    for entry in sort_spec:
        if isinstance(entry, str):
            sort_keys.append((entry, False))
        elif isinstance(entry, dict):
            for field, opts in entry.items():
                if isinstance(opts, dict):
                    desc = opts.get("order", "asc") == "desc"
                else:
                    desc = str(opts).lower() == "desc"
                sort_keys.append((field, desc))

    result = list(records)
    for field, reverse in reversed(sort_keys):
        def _make_key(f: str) -> Callable[[dict], tuple[int, Any]]:
            def key(rec: dict) -> tuple[int, Any]:
                return _sort_key(_get_nested(rec, f))
            return key
        result.sort(key=_make_key(field), reverse=reverse)
    return result


def _sort_key(val: Any) -> tuple[int, Any]:
    """Produce a sort key that handles ``None`` and mixed types gracefully.

    Nones sort last.  Numerics and strings are kept in their natural order.
    """
    if val is None:
        return (1, "")
    if isinstance(val, (int, float)):
        return (0, val)
    return (0, str(val))


# ---------------------------------------------------------------------------
# Hit wrapping
# ---------------------------------------------------------------------------

def wrap_as_hits(
    records: list[dict],
    index: str = ".siem-signals-default",
) -> list[dict]:
    """Wrap plain dicts as Elasticsearch hit objects.

    Each record is wrapped with ``_index``, ``_id``, ``_score``, and
    ``_source`` keys, matching the Elasticsearch ``hits.hits[]`` format.

    Args:
        records: List of plain dicts.
        index:   Index name to set on each hit.

    Returns:
        List of Elasticsearch-style hit dicts.
    """
    return [
        {
            "_index": index,
            "_id": _hit_id(rec),
            "_score": 1.0,
            "_source": rec,
        }
        for rec in records
    ]


def _hit_id(rec: dict) -> str:
    """Derive a stable ``_id`` for a record.

    A fresh UUID per response meant the same document came back under a
    different ``_id`` every call, so search → get-by-id, dedup, and
    alert-status updates could never round-trip. The document's own
    identifier is used where it has one; anything else gets a digest of its
    contents so the value is at least stable for identical input.
    """
    for field in ("id", "_id", "rule_id", "item_id", "list_id"):
        val = rec.get(field)
        if isinstance(val, str) and val:
            return val
    # ECS alert documents carry their identity nested.
    for path in ("kibana.alert.uuid", "signal.rule.id"):
        nested = _get_nested(rec, path)
        if isinstance(nested, str) and nested:
            return nested
    digest = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode())
    return str(uuid.UUID(digest.hexdigest()[:32]))


# ---------------------------------------------------------------------------
# _source filtering
# ---------------------------------------------------------------------------

def _as_patterns(spec: object) -> list[str]:
    """Normalise a ``_source`` include/exclude spec to a list of patterns."""
    if isinstance(spec, str):
        return [spec]
    if isinstance(spec, (list, tuple)):
        return [str(p) for p in spec]
    return []


def _project(record: dict, includes: list[str], excludes: list[str]) -> dict:
    """Keep the fields matching *includes* and drop those matching *excludes*.

    Patterns may use ``*`` and may name a dotted path, matching Elasticsearch's
    source-filtering syntax.
    """
    def keep(field: str) -> bool:
        if includes and not any(fnmatch(field, p) for p in includes):
            return False
        return not any(fnmatch(field, p) for p in excludes)

    return {field: value for field, value in record.items() if keep(field)}


def apply_source_filter(hits: list[dict], spec: object) -> list[dict]:
    """Apply a ``_search`` body's ``_source`` directive to built hits.

    ``_source`` was read and ignored, so a client asking for two fields got
    every field — the response was larger than it asked for and matched
    nothing a real cluster would send.

    ``false`` drops ``_source`` entirely; a list or string keeps only the
    matching fields; a dict takes ``includes``/``excludes``.
    """
    if spec is None or spec is True:
        return hits

    if spec is False:
        return [{k: v for k, v in hit.items() if k != "_source"} for hit in hits]

    if isinstance(spec, dict):
        includes = _as_patterns(spec.get("includes") or spec.get("include"))
        excludes = _as_patterns(spec.get("excludes") or spec.get("exclude"))
    else:
        includes, excludes = _as_patterns(spec), []

    if not includes and not excludes:
        return hits

    return [
        {**hit, "_source": _project(hit.get("_source", {}), includes, excludes)}
        for hit in hits
    ]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def apply_es_query(records: list[dict], query_body: dict) -> list[dict]:
    """Apply an Elasticsearch query DSL body to a list of records.

    The *query_body* is the full ``_search`` request body dict.  Extracts
    the ``query`` key and applies it as a filter.  Also handles ``sort``,
    ``from`` (offset), and ``size`` (limit).

    Args:
        records:    List of dicts to filter.
        query_body: Elasticsearch ``_search`` request body.

    Returns:
        Filtered, sorted, and paginated records.
    """
    # Filter.
    query_clause = query_body.get("query")
    if query_clause:
        predicate = _build_predicate(query_clause)
        records = [r for r in records if predicate(r)]

    # Sort.
    sort_spec = query_body.get("sort")
    if sort_spec:
        records = apply_es_sort(records, sort_spec)

    # Paginate.
    offset = query_body.get("from", 0)
    # ES defaults to 10; returning the whole index let a client that never sets
    # size look like it worked against a seeded mock and then truncate in prod.
    size = query_body.get("size", _DEFAULT_SIZE)
    if offset:
        records = records[offset:]
    if size is not None:
        records = records[:size]

    return records
