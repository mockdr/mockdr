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
from datetime import datetime
from fnmatch import fnmatch
from typing import Any, NamedTuple

from utils.es_datemath import ROUNDS_UP, DateMathError, is_date_math
from utils.es_datemath import parse_datetime as parse_es_datetime
from utils.es_datemath import resolve as resolve_date_math
from utils.nested import get_nested as _get_nested

_DEFAULT_SIZE = 10

#: Mirrors Elasticsearch's indices.query.bool.max_nested_depth default.
_MAX_CLAUSE_DEPTH = 30


#: Every key a search body may carry. Elasticsearch refuses any other with
#: parsing_exception "Unknown key for a START_OBJECT in [x]." (measured on
#: 8.15); mockdr ignored unknown keys and answered every hit.
_KNOWN_TOP_LEVEL: frozenset[str] = frozenset({
    "query", "size", "from", "sort", "aggs", "aggregations", "_source", "fields",
    "track_total_hits", "search_after", "highlight", "collapse", "post_filter",
    "stored_fields", "docvalue_fields", "script_fields", "min_score", "explain",
    "version", "seq_no_primary_term", "timeout", "terminate_after", "pit",
    "runtime_mappings", "suggest", "rescore", "indices_boost", "track_scores",
    "profile", "slice", "knn", "ext", "stats", "rank", "retriever",
})

_JSON_TOKENS = {
    dict: "START_OBJECT", list: "START_ARRAY", str: "VALUE_STRING", bool: "VALUE_TRUE",
    int: "VALUE_NUMBER", float: "VALUE_NUMBER", type(None): "VALUE_NULL",
}

#: Elasticsearch's default index.max_result_window.
MAX_RESULT_WINDOW = 10000


def validate_search_body(body: dict) -> None:
    """Refuse what Elasticsearch refuses before it looks at the query.

    Raises:
        ESQueryError: For an unknown top-level key, or a result window past
            ``index.max_result_window``.
    """
    for key, value in body.items():
        if key not in _KNOWN_TOP_LEVEL:
            token = _JSON_TOKENS.get(type(value), "VALUE_STRING")
            if value is False:
                token = "VALUE_FALSE"
            raise ESQueryError(f"Unknown key for a {token} in [{key}].", clause=key)
    search_after = body.get("search_after")
    if search_after is not None:
        sort_keys = parse_sort_keys(body.get("sort") or [])
        if not emits_sort_values(sort_keys):
            raise ESQueryError(
                "Sort must contain at least one field.",
                es_type="illegal_argument_exception",
            )
        if len(search_after) != len(sort_keys):
            # The real message, because a client that pages wrongly needs to
            # see why rather than an empty page.
            raise ESQueryError(
                f"search_after has {len(search_after)} value(s) but sort has "
                f"{len(sort_keys)}.",
                es_type="illegal_argument_exception",
            )
    start = _as_bound(body.get("from"), "from") or 0
    size = _as_bound(body.get("size"), "size")
    size = 10 if size is None else size
    if start + size > MAX_RESULT_WINDOW:
        raise ESQueryError(
            f"Result window is too large, from + size must be less than or equal to: "
            f"[{MAX_RESULT_WINDOW}] but was [{start + size}]. See the scroll api for a more "
            f"efficient way to request large data sets. This limit can be set by changing "
            f"the [index.max_result_window] index level setting.",
            es_type="search_phase_execution_exception",
        )


class ESQueryError(ValueError):
    """Raised when a search body is not valid Elasticsearch query DSL.

    Elasticsearch answers a malformed or unknown query with a 400 carrying
    ``parsing_exception``; these previously escaped as bare ``ValueError`` and
    surfaced as a plain-text 500.

    ``clause`` names the unknown query type when that is the failure, so the
    handler can render the ``caused_by`` and body position Elasticsearch
    attaches to that case and no other.
    """

    def __init__(
        self, message: str, *, clause: str | None = None,
        es_type: str = "parsing_exception", named_object: bool = False,
    ) -> None:
        """Record the message, the clause if any, and Elasticsearch's exception type.

        ``named_object`` marks the one case that carries a ``caused_by``:
        an unknown query or aggregation *type*. An unknown top-level key is
        a parsing_exception too, but without the cause (measured on 8.15).
        """
        super().__init__(message)
        self.clause = clause
        self.es_type = es_type
        self.named_object = named_object

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

def build_predicate(clause: dict, _depth: int = 0) -> Callable[[dict], bool]:
    """Recursively build a predicate function from an ES query clause.

    Args:
        clause: A single Elasticsearch query clause dict.
        _depth: Recursion guard for nested ``bool`` clauses.

    Returns:
        A callable that accepts a record dict and returns ``True`` on match.

    Raises:
        ESQueryError: If the clause is unsupported or nested too deeply.
    """
    # Elasticsearch caps nesting at indices.query.bool.max_nested_depth for
    # exactly this reason: without a bound, a deeply nested bool exhausts the
    # stack and the RecursionError escapes as a 500.
    if _depth > _MAX_CLAUSE_DEPTH:
        msg = f"[bool] query is nested too deeply, max depth is {_MAX_CLAUSE_DEPTH}"
        raise ESQueryError(msg)

    if not clause:
        return lambda _rec: True

    if not isinstance(clause, dict):
        msg = f"[query] malformed query, expected an object but found {type(clause).__name__}"
        raise ESQueryError(msg)

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
            # Elasticsearch 8 says "unknown query"; "no [query] registered"
            # was the 6.x/7.x wording.
            raise ESQueryError(
                f"unknown query [{query_type}]", clause=query_type, named_object=True,
            )
        if not isinstance(body, dict):
            # A clause body of null or a scalar reached the builders as-is and
            # raised AttributeError out of the handler as a plain-text 500.
            msg = f"[{query_type}] query malformed, expected an object"
            raise ESQueryError(msg)
        if query_type == "bool":
            return _build_bool(body, _depth + 1)
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

    terms = _analyze(query)

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None:
            return False
        # Match against analysed tokens, not raw substrings: `match: "SERV"`
        # used to hit "SERVER-KQEZSV", which no analyzer produces.
        tokens = set(_analyze_value(val))
        if operator == "and":
            return all(t in tokens for t in terms)
        return any(t in tokens for t in terms)

    return predicate


def _build_match_phrase(body: dict) -> Callable[[dict], bool]:
    """Build predicate for ``match_phrase``.

    Exact phrase match (case-insensitive).
    """
    field, spec = next(iter(body.items()))
    query = spec.get("query", "") if isinstance(spec, dict) else spec
    phrase = _analyze(str(query))

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        if val is None:
            return False
        # A phrase is a contiguous run of tokens, not a substring.
        tokens = _analyze_value(val)
        if not phrase:
            return False
        span = len(phrase)
        return any(
            tokens[i : i + span] == phrase for i in range(len(tokens) - span + 1)
        )

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
    """Build predicate for ``range``.

    A bound written as date math (``now-30d``, ``now/d``) is resolved once,
    here, so every document in one search sees the same ``now`` — as it does
    in Elasticsearch. Rounding direction comes from the operator, which is
    what makes ``gte: "now/d"`` mean *since midnight* and ``lte: "now/d"``
    *through the end of today*.
    """
    field, bounds = next(iter(body.items()))
    time_zone = bounds.get("time_zone") if isinstance(bounds, dict) else None

    resolved: list[tuple[str, Any, datetime | None]] = []
    for op, target in bounds.items():
        # Ignore non-operator keys like "format", "time_zone", "boost".
        if op not in ("gte", "gt", "lte", "lt"):
            continue
        moment: datetime | None = None
        if is_date_math(target):
            try:
                moment = resolve_date_math(
                    target, round_up=ROUNDS_UP[op], time_zone=time_zone,
                )
            except DateMathError as exc:
                raise ESQueryError(str(exc), es_type="parse_exception") from exc
        resolved.append((op, target, moment))

    def predicate(rec: dict) -> bool:
        val = _get_nested(rec, field)
        for op, target, moment in resolved:
            if moment is not None:
                if not _compare_moment(val, moment, op):
                    return False
            elif not _compare_range(val, target, op):
                return False
        return True

    return predicate


def _compare_moment(field_val: Any, bound: datetime, op: str) -> bool:
    """Compare a stored value against a resolved instant.

    A value that is not a date cannot be inside a date window; Elasticsearch
    would have rejected it at index time against a ``date`` mapping.
    """
    moment = parse_es_datetime(field_val)
    if moment is None:
        return False
    if op == "gte":
        return moment >= bound
    if op == "gt":
        return moment > bound
    if op == "lte":
        return moment <= bound
    return moment < bound


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


def _build_bool(body: dict, depth: int = 0) -> Callable[[dict], bool]:
    """Build predicate for ``bool`` query.

    Combines ``must``, ``filter``, ``should``, and ``must_not`` sub-clauses.
    The depth is threaded through so nesting stays bounded.
    """
    must_preds = [build_predicate(c, depth) for c in body.get("must", [])]
    filter_preds = [build_predicate(c, depth) for c in body.get("filter", [])]
    should_preds = [build_predicate(c, depth) for c in body.get("should", [])]
    must_not_preds = [build_predicate(c, depth) for c in body.get("must_not", [])]
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
    \b(?P<not_>NOT)\b                       # NOT keyword
    | \b(?P<and_>AND)\b                     # AND keyword
    | \b(?P<or_>OR)\b                       # OR keyword
    # ``@`` leads the name of every ECS timestamp; without it `@timestamp:x`
    # tokenised as a bare word and searched every field instead of that one.
    | (?P<field>[A-Za-z_@][A-Za-z0-9_.@\-]*):
                                            # field name followed by colon
      (?:"(?P<quoted>[^"]*)"                # quoted value
      |(?P<ranged>[\[{][^\]}]*[\]}])        # [a TO b] / {a TO b} range
      |(?P<bare>\S+))                       # unquoted value
    | "(?P<phrase>[^"]*)"                   # bare quoted phrase (default field)
    | (?P<word>\S+)                         # bare word (default field)
    """,
    re.VERBOSE,
)

#: ``[a TO b]`` and ``{a TO b}`` — square brackets include the bound, braces
#: exclude it, and the two ends may differ.
_QS_RANGE_RE = re.compile(r"^([\[{])\s*(\S+)\s+TO\s+(\S+)\s*([\]}])$")

#: ``field:>=5`` — the shorthand Lucene allows for a one-sided range.
_QS_CMP_RE = re.compile(r"^(>=|<=|>|<)(.+)$")


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
        if m.group("not_"):
            tokens.append(("NOT", "", ""))
        elif m.group("and_"):
            tokens.append(("AND", "", ""))
        elif m.group("or_"):
            tokens.append(("OR", "", ""))
        elif m.group("field"):
            for group in ("quoted", "ranged", "bare"):
                value = m.group(group)
                if value is not None:
                    break
            tokens.append(("term", m.group("field"), value or ""))
        elif m.group("phrase") is not None:
            tokens.append(("term", "", m.group("phrase")))
        elif m.group("word"):
            tokens.append(("term", "", m.group("word")))
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
    if field:
        ranged = _qs_range_pred(field, value)
        if ranged is not None:
            return ranged

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


def _qs_range_pred(field: str, value: str) -> Callable[[dict], bool] | None:
    """Build a predicate for Lucene's range spellings, or ``None`` if absent.

    ``field:[a TO b]`` includes both bounds, ``{a TO b}`` excludes them, and
    the two ends may differ; ``field:>=5`` is the one-sided shorthand. ``*``
    means unbounded. Detection rules and Kibana's Lucene mode write their
    time windows this way, and until now every one of them tokenised as a
    substring match that could not hit.
    """
    bounds: dict[str, str] = {}

    match = _QS_RANGE_RE.match(value)
    if match:
        left, lower, upper, right = match.groups()
        if lower != "*":
            bounds["gte" if left == "[" else "gt"] = lower
        if upper != "*":
            bounds["lte" if right == "]" else "lt"] = upper
    else:
        cmp_match = _QS_CMP_RE.match(value)
        if not cmp_match:
            return None
        symbol, operand = cmp_match.groups()
        bounds[{">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[symbol]] = operand

    if not bounds:
        # `field:[* TO *]` bounds nothing, which is an existence check.
        return lambda rec: _get_nested(rec, field) is not None
    return _build_range({field: bounds})


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

class SortKey(NamedTuple):
    """One key of a sort, as the DSL spells it.

    Attributes:
        field:         Field to sort on, or ``_score`` / ``_doc``.
        desc:          Whether the order is descending.
        missing_first: Whether documents lacking the field come first;
                       Elasticsearch's default is last, in *both* directions.
    """

    field: str
    desc: bool = False
    missing_first: bool = False


def parse_sort_keys(sort_spec: list) -> list[SortKey]:
    """Read a sort array as ``SortKey`` entries, in priority order.

    Accepts every spelling the DSL allows: ``"field"``, ``{"field": "desc"}``
    and ``{"field": {"order": "desc", "missing": "_first"}}``.
    """
    sort_keys: list[SortKey] = []
    for entry in sort_spec:
        if isinstance(entry, str):
            sort_keys.append(SortKey(entry))
        elif isinstance(entry, dict):
            for field, opts in entry.items():
                if isinstance(opts, dict):
                    desc = opts.get("order", "asc") == "desc"
                    missing_first = opts.get("missing") == "_first"
                else:
                    desc = str(opts).lower() == "desc"
                    missing_first = False
                sort_keys.append(SortKey(field, desc, missing_first))
    return sort_keys


def doc_positions(records: list[dict]) -> dict[int, int]:
    """Give each record the stable position ``_doc`` sorts and reports on.

    Elasticsearch numbers documents by their position in the index; here that
    is their position in the resolved collection, which is insertion order.
    Keyed by identity so the number survives sorting and paging.
    """
    return {id(record): position for position, record in enumerate(records)}


def emits_sort_values(sort_keys: list[SortKey]) -> bool:
    """Whether this sort makes Elasticsearch attach a ``sort`` array to hits.

    A search sorted only by ``_score`` is still a scored search: it keeps its
    scores and carries no sort values, so it cannot be paged with
    ``search_after`` either.
    """
    return any(key.field != "_score" for key in sort_keys)


def sort_values(
    record: dict,
    sort_keys: list[SortKey],
    positions: dict[int, int] | None = None,
) -> list:
    """The ``sort`` array Elasticsearch attaches to a hit when a sort is given.

    Without it no client can page with ``search_after`` — the recommended way
    past the 10 000-document result window, and what every Elastic SIEM
    integration uses to pull a backlog. A date comes back as epoch
    milliseconds, the way a ``date`` field's doc values do; ``_doc`` is the
    document's position and ``_score`` its score.
    """
    values: list = []
    for key in sort_keys:
        if key.field == "_doc":
            values.append((positions or {}).get(id(record), 0))
        elif key.field == "_score":
            values.append(1.0)
        else:
            values.append(_sort_value(_get_nested(record, key.field)))
    return values


def _sort_value(value: Any) -> Any:
    """Render one field value as its doc-value form for a ``sort`` array."""
    if isinstance(value, str) and _LOOKS_LIKE_DATE.match(value):
        moment = parse_es_datetime(value)
        if moment is not None:
            return int(moment.timestamp() * 1000)
    if isinstance(value, (list, tuple, set)):
        # A multi-valued field sorts on one member; ES picks min for asc, but
        # the array itself is never the sort value.
        return _sort_value(min((str(v) for v in value), default=None))
    return value


#: ``2026-08-06`` or ``2026-08-06T16:16:51.000Z`` — enough to tell a date
#: string from a keyword before paying for a parse.
_LOOKS_LIKE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]|$)")


def apply_search_after(
    records: list[dict],
    search_after: list,
    sort_keys: list[SortKey],
    positions: dict[int, int] | None = None,
) -> list[dict]:
    """Keep only the records that follow *search_after* in the sort order.

    Args:
        records:      Records already in sorted order.
        search_after: The ``sort`` array of the last hit of the previous page.
        sort_keys:    Parsed sort keys, in priority order.
        positions:    Document positions, for a ``_doc`` sort key.

    Returns:
        The tail of *records* strictly after that point.
    """
    return [
        record
        for record in records
        if _follows(sort_values(record, sort_keys, positions), search_after, sort_keys)
    ]


def _follows(values: list, target: list, sort_keys: list[SortKey]) -> bool:
    """Whether *values* sorts strictly after *target* under *sort_keys*."""
    for value, bound, key in zip(values, target, sort_keys, strict=False):
        left, right = _sort_key(value), _sort_key(bound)
        if left == right:
            continue
        # A number against a string is a client error, not a crash: the two
        # tuples would raise rather than compare.
        numeric = isinstance(left[1], (int, float)) and isinstance(right[1], (int, float))
        if left[0] == right[0] and not numeric and type(left[1]) is not type(right[1]):
            return False
        return left < right if key.desc else left > right
    # Exactly equal to the previous page's last hit: that document is behind
    # us, not ahead of us.
    return False


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

    sort_keys = parse_sort_keys(sort_spec)
    result = list(records)
    for key in reversed(sort_keys):
        # `_score` and `_doc` are metadata, not `_source` fields. Looking them
        # up nested found nothing and bucketed every document equally, so the
        # sort silently did nothing. Every document scores the same here, and
        # `_doc` is index order, so both preserve the current order.
        if key.field in ("_score", "_doc"):
            continue

        # A document without the field sorts last whichever way the order
        # runs — Elasticsearch's `missing: "_last"` default. Since the list
        # sort reverses every part of the key, the group has to be inverted
        # for a descending sort to keep those documents at the end. They used
        # to lead a descending sort, so "the newest N alerts" answered with
        # the ones carrying no timestamp at all.
        absent_group = int(bool(key.missing_first) == bool(key.desc))

        def _make_key(field: str, absent: int) -> Callable[[dict], tuple[int, Any]]:
            def sort_key(rec: dict) -> tuple[int, Any]:
                value = _get_nested(rec, field)
                if value is None:
                    return (absent, "")
                return (1 - absent, _sort_key(value)[1])
            return sort_key

        result.sort(key=_make_key(key.field, absent_group), reverse=key.desc)
    return result


_TOKEN_SPLIT = re.compile(r"[^0-9A-Za-z_]+")


def _analyze(text: str) -> list[str]:
    """Split text the way Elasticsearch's standard analyzer would."""
    return [t for t in _TOKEN_SPLIT.split(str(text).lower()) if t]


def _analyze_value(value: Any) -> list[str]:
    """Analyse a field value, flattening arrays as ES does."""
    if isinstance(value, (list, tuple, set)):
        tokens: list[str] = []
        for item in value:
            tokens.extend(_analyze(str(item)))
        return tokens
    return _analyze(str(value))


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
    sort_keys: list[SortKey] | None = None,
    positions: dict[int, int] | None = None,
) -> list[dict]:
    """Wrap plain dicts as Elasticsearch hit objects.

    Each record is wrapped with ``_index``, ``_id``, ``_score``, and
    ``_source`` keys, matching the Elasticsearch ``hits.hits[]`` format.

    Args:
        records:   List of plain dicts.
        index:     Index name to set on each hit.
        sort_keys: Parsed sort keys; when given, each hit carries the ``sort``
                   array a client needs to page with ``search_after``.
        positions: Document positions, for a ``_doc`` sort key.

    Returns:
        List of Elasticsearch-style hit dicts.
    """
    hits: list[dict[str, Any]] = []
    for rec in records:
        hit: dict[str, Any] = {
            "_index": index,
            "_id": hit_id(rec),
            # A sorted search has no relevance score in Elasticsearch.
            "_score": None if sort_keys else 1.0,
            "_source": rec,
        }
        if sort_keys:
            hit["sort"] = sort_values(rec, sort_keys, positions)
        hits.append(hit)
    return hits


def hit_id(rec: dict) -> str:
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


def _as_bound(value: Any, name: str) -> int | None:
    """Coerce a ``from``/``size`` bound, rejecting what Elasticsearch rejects."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        msg = f"[{name}] must be a number"
        raise ESQueryError(msg)
    try:
        bound = int(value)
    except (TypeError, ValueError) as exc:
        # Elasticsearch reports Java's NumberFormatException verbatim.
        msg = f'For input string: "{value}"'
        raise ESQueryError(msg, es_type="number_format_exception") from exc
    if bound < 0:
        msg = f"[{name}] parameter cannot be negative, found [{bound}]"
        raise ESQueryError(msg, es_type="illegal_argument_exception")
    return bound


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
    positions = doc_positions(records)

    # Filter.
    query_clause = query_body.get("query")
    if query_clause:
        predicate = build_predicate(query_clause)
        records = [r for r in records if predicate(r)]

    # Sort.
    sort_spec = query_body.get("sort")
    if sort_spec:
        records = apply_es_sort(records, sort_spec)
        search_after = query_body.get("search_after")
        if search_after:
            records = apply_search_after(
                records, search_after, parse_sort_keys(sort_spec), positions,
            )

    # Paginate.
    # ES rejects a non-numeric from/size; slicing by one raised TypeError out
    # of the handler as a plain-text 500.
    offset = _as_bound(query_body.get("from", 0), "from")
    # ES defaults to 10; returning the whole index let a client that never sets
    # size look like it worked against a seeded mock and then truncate in prod.
    size = _as_bound(query_body.get("size", _DEFAULT_SIZE), "size")
    if offset:
        records = records[offset:]
    if size is not None:
        records = records[:size]

    return records
