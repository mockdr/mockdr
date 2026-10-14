"""Graph API OData extensions — wraps ``mde_odata`` with Graph-specific syntax.

The existing ``mde_odata`` module handles basic OData ``$filter`` (eq, ne, gt,
ge, lt, le, contains, startswith, and, or).  This module extends it with:

- ``$count`` support (``$count=true`` with ``ConsistencyLevel: eventual``)
- ``$search`` support (``"displayName:John"`` substring matching)
- Lambda-expression pre-processing (``assignedLicenses/any(...)`` → flattened)
- Nested slash-path normalisation (``signInActivity/lastSignInDateTime`` → dot)
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException

from utils.graph_response import build_graph_error_response
from utils.mde_odata import (
    apply_odata_filter,
    apply_odata_orderby,
    apply_odata_select,
)

# Re-export so callers can import everything from one place
__all__ = [
    "select_fields",
    "apply_odata_filter",
    "apply_odata_orderby",
    "apply_odata_select",
    "apply_graph_filter",
    "apply_odata_count",
    "apply_odata_search",
    "require_advanced_query",
]

def select_fields(record: dict | None, select: str | None) -> dict | None:
    """Project one resource through ``$select``.

    The collection form of this is :func:`apply_odata_select`; a single
    resource needs the same projection, and the ``@odata`` annotations
    survive it because they describe the answer rather than the resource.
    """
    if record is None or not select or not select.strip():
        return record
    fields = {f.strip() for f in select.split(",") if f.strip()}
    return {
        key: value for key, value in record.items()
        if key in fields or key.startswith("@")
    }


# ---------------------------------------------------------------------------
# Lambda pre-processor
# ---------------------------------------------------------------------------

# The leading anchor matters for more than tidiness: without it the engine
# retries the match at every offset inside a long word run, and each retry
# scans to the end — quadratic. A 32KB filter took 2.8s to reject, so a handful
# of concurrent requests could stall a worker. `\b` fixed that for a run of
# letters but not for `a/a/a/...`, where every segment starts a word: 32KB of
# it took over 7s across the three patterns below. `(?<![\w/])` anchors to the
# start of the whole path instead, which is linear for both.

#: A literal operand: a quoted string, or an unquoted GUID, number or keyword
#: (``assignedLicenses/any(s:s/skuId eq 184efa21-98c3-...)`` is the docs' own
#: example, and the quoted-only pattern refused it).
_LITERAL = r"('(?:[^']|'')*'|[\w.:+-]+)"

_LAMBDA_RE = re.compile(
    r"(?<![\w/])(\w[\w/]*)/any\s*\(\s*(\w+)\s*:\s*\2/(\w+)\s+"
    r"(eq|ne|gt|ge|lt|le)\s+"
    + _LITERAL + r"\s*\)",
    re.IGNORECASE,
)

#: A lambda over a collection of primitives, where the range variable is the
#: member itself: ``groupTypes/any(c:c eq 'Unified')``,
#: ``businessPhones/any(p:startswith(p, '44'))``. Both forms are documented
#: (https://learn.microsoft.com/en-us/graph/filter-query-parameter, "any"
#: tables) and the mock refused them with a parse error. ``ne`` is left out:
#: ``any(c: c ne 'x')`` means "some member differs", which the flat rewrite
#: below cannot say.
_PRIMITIVE_LAMBDA_RE = re.compile(
    r"(?<![\w/])(\w[\w/]*)/any\s*\(\s*(\w+)\s*:\s*\2\s+(eq|gt|ge|lt|le)\s+"
    + _LITERAL + r"\s*\)",
    re.IGNORECASE,
)
_PRIMITIVE_LAMBDA_FUNC_RE = re.compile(
    r"(?<![\w/])(\w[\w/]*)/any\s*\(\s*(\w+)\s*:\s*(startswith|endswith|contains)\s*\(\s*\2\s*,\s*"
    r"('(?:[^']|'')*')\s*\)\s*\)",
    re.IGNORECASE,
)


def _preprocess_lambda(filter_str: str) -> str:
    """Rewrite OData lambda expressions into flat contains-style checks.

    ``assignedLicenses/any(l: l/skuId eq '...')``
    →  ``_lambda_match_assignedLicenses_skuId eq '...'``

    and, over a collection of primitives,

    ``groupTypes/any(c: c eq 'Unified')`` → ``groupTypes eq 'Unified'``
    ``businessPhones/any(p: startswith(p, '44'))`` → ``startswith(businessPhones, '44')``

    which mean the same thing, because a comparison against a list-valued
    field matches when any member does (``utils/mde_odata._match_clause``).
    The sub-property form is resolved by :func:`_match_lambda_field`.
    """
    rewritten = _LAMBDA_RE.sub(r"_lambda_\1_\3 \4 \5", filter_str)
    rewritten = _PRIMITIVE_LAMBDA_RE.sub(r"\1 \3 \4", rewritten)
    return _PRIMITIVE_LAMBDA_FUNC_RE.sub(r"\3(\1, \4)", rewritten)


def _normalise_slash_paths(filter_str: str) -> str:
    """Convert slash-separated field paths to dot-separated.

    ``signInActivity/lastSignInDateTime`` → ``signInActivity.lastSignInDateTime``

    Skips paths already handled by the lambda pre-processor (starting with
    ``_lambda_``).
    """
    def _replace(m: re.Match[str]) -> str:
        word = m.group(0)
        if word.startswith("_lambda_"):
            return word
        return word.replace("/", ".")

    return re.sub(r"[A-Za-z_][\w./]*", _replace, filter_str)


# ---------------------------------------------------------------------------
# Graph-aware filter
# ---------------------------------------------------------------------------

def _match_lambda_field(record: dict, field: str) -> Any:  # noqa: ANN401
    """Resolve a synthetic ``_lambda_collection_prop`` field.

    For example, ``_lambda_assignedLicenses_skuId`` iterates
    ``record["assignedLicenses"]`` and collects every ``skuId``. The values are
    returned as a list so the comparison matches when *any* member matches —
    joining them into one pipe-separated string meant the clause only ever
    matched a record whose collection held exactly one item.
    """
    if not field.startswith("_lambda_"):
        return None
    parts = field[len("_lambda_"):].split("_", 1)
    if len(parts) != 2:
        return None
    collection_name, prop = parts
    items = record.get(collection_name)
    if not isinstance(items, list):
        return None
    return [str(item.get(prop, "")) for item in items if isinstance(item, dict)]


def apply_graph_filter(records: list[dict], filter_str: str) -> list[dict]:
    """Apply an OData ``$filter`` expression with Graph-specific extensions.

    Pre-processes lambda expressions and slash-paths, then delegates to the
    standard MDE OData filter engine.

    Args:
        records:    List of dicts to filter.
        filter_str: OData filter string (may contain Graph extensions).

    Returns:
        Filtered subset matching all conditions.
    """
    if not filter_str or not filter_str.strip():
        return list(records)

    processed = _preprocess_lambda(filter_str)
    processed = _normalise_slash_paths(processed)

    # Inject lambda field values into records temporarily
    has_lambda = "_lambda_" in processed
    if has_lambda:
        # The synthetic field names come from the filter, not from the data:
        # scanning the filter string again for every record re-ran the same
        # regex once per document.
        lambda_fields = sorted({m.group(0) for m in re.finditer(r"_lambda_\w+", processed)})
        for record in records:
            for lf in lambda_fields:
                record[lf] = _match_lambda_field(record, lf)

    # try/finally: a malformed filter now raises, and leaking the synthetic
    # _lambda_* keys back to the caller would corrupt the records themselves.
    try:
        # Graph documents `in` (filter-query-parameter: "In (`in`)").
        result = apply_odata_filter(records, processed, allow_in=True)
    finally:
        if has_lambda:
            for record in records:
                for key in list(record.keys()):
                    if key.startswith("_lambda_"):
                        del record[key]

    return result


# ---------------------------------------------------------------------------
# $count
# ---------------------------------------------------------------------------

def apply_odata_count(
    records: list[dict],
    count_param: bool | str | None,
    consistency_level: str | None = None,
    *,
    refuse_without_header: bool = False,
) -> int | None:
    """Return the total count if ``$count=true`` and ConsistencyLevel allows it.

    On directory objects Graph counts only in an advanced query, and without
    the header it "silently ignores the $count query parameter (?$count=true)"
    (https://learn.microsoft.com/en-us/graph/aad-advanced-queries#error-handling-for-advanced-queries-on-directory-objects).
    The mock answered 400 there instead, on the stated belief that Graph
    rejects it; the documented answer is a 200 without ``@odata.count``.

    Args:
        records:               All records (pre-filter).
        count_param:           Value of the ``$count`` query parameter.
        consistency_level:     Value of the ``ConsistencyLevel`` header.
        refuse_without_header: Keep the earlier 400 for a route whose product
                               behaviour has not been measured (Intune's
                               managedDevices), rather than change it unseen.

    Returns:
        Total count, or ``None`` if ``$count`` is not requested or the header
        is missing.
    """
    if not count_param:
        return None
    count_requested = str(count_param).lower() in ("true", "1")
    if not count_requested:
        return None

    if not _is_eventual(consistency_level):
        if not refuse_without_header:
            return None
        raise HTTPException(
            status_code=400,
            detail=build_graph_error_response(
                "Request_UnsupportedQuery",
                "Request with $count is only supported with "
                "ConsistencyLevel:eventual header.",
            ),
        )

    return len(records)


def _is_eventual(consistency_level: str | None) -> bool:
    """Whether the caller opted into eventual consistency."""
    return (consistency_level or "").strip().lower() == "eventual"


#: Filter operators that directory objects serve only in an advanced query
#: (https://learn.microsoft.com/en-us/graph/aad-advanced-queries#query-scenarios-that-require-advanced-query-capabilities:
#: "Use of $filter with the endsWith operator", "with ne and not operators").
_ADVANCED_OPERATOR = re.compile(r"\b(endsWith)\s*\(|\s(ne)\s|\b(not)\b", re.IGNORECASE)
_QUOTED = re.compile(r"'(?:[^']|'')*'")


def require_advanced_query(
    *,
    filter_str: str | None,
    orderby: str | None,
    search: str | None,
    count_param: bool | str | None,
    consistency_level: str | None,
) -> None:
    """Refuse a directory query that needs the advanced query parameters.

    "The requestor must set the ConsistencyLevel header to eventual and,
    except for $search, use the $count query parameter"; without them "the
    request returns an error"
    (https://learn.microsoft.com/en-us/graph/aad-advanced-queries). The mock
    checked the header only for ``$count`` and served ``$search``,
    ``endsWith``, ``ne``, ``not`` and ``$filter`` with ``$orderby`` to any
    caller -- so an integration could ship a query production refuses.

    The ``$search`` and ``endsWith`` messages are the documented ones; ``ne``
    and ``not`` take the ``endsWith`` wording with their own operator, and
    ``$filter`` with ``$orderby`` a message of the same family, as the docs
    record neither verbatim.

    Raises:
        HTTPException: 400 ``Request_UnsupportedQuery``.
    """
    eventual = _is_eventual(consistency_level)
    if search and search.strip() and not eventual:
        raise HTTPException(status_code=400, detail=build_graph_error_response(
            "Request_UnsupportedQuery",
            "Request with $search query parameter only works through MSGraph with a "
            "special request header: 'ConsistencyLevel: eventual'",
        ))
    counted = str(count_param).lower() in ("true", "1") if count_param else False
    if eventual and counted:
        return
    if not filter_str or not filter_str.strip():
        return
    match = _ADVANCED_OPERATOR.search(_QUOTED.sub("''", filter_str))
    if match:
        operator = next(group for group in match.groups() if group)
        raise HTTPException(status_code=400, detail=build_graph_error_response(
            "Request_UnsupportedQuery",
            f"Operator '{operator}' is not supported because the required parameters "
            f"might be missing. Try adding $count=true query parameter and "
            f"ConsistencyLevel:eventual header. Refer to "
            f"https://aka.ms/graph-docs/advanced-queries for more information",
        ))
    if orderby and orderby.strip():
        raise HTTPException(status_code=400, detail=build_graph_error_response(
            "Request_UnsupportedQuery",
            "Sorting and filtering in the same query is not supported because the "
            "required parameters might be missing. Try adding $count=true query "
            "parameter and ConsistencyLevel:eventual header. Refer to "
            "https://aka.ms/graph-docs/advanced-queries for more information",
        ))


# ---------------------------------------------------------------------------
# $search
# ---------------------------------------------------------------------------

def apply_odata_search(
    records: list[dict],
    search_str: str | None,
    fields: list[str] | None = None,
) -> list[dict]:
    """Apply OData ``$search`` to records.

    Graph ``$search`` format: ``"displayName:John"`` or plain ``"John"``.
    Performs case-insensitive substring matching on specified fields
    (defaults to ``displayName``, ``userPrincipalName``, ``mail``).

    Args:
        records:    List of dicts to search.
        search_str: Search string (with optional quotes and field prefix).
        fields:     Fields to search in (defaults to common identity fields).

    Returns:
        Matching records.
    """
    if not search_str or not search_str.strip():
        return list(records)

    if fields is None:
        fields = ["displayName", "userPrincipalName", "mail"]

    # Strip surrounding quotes
    query = search_str.strip().strip('"')

    # Parse "field:value" format
    target_field = None
    if ":" in query:
        parts = query.split(":", 1)
        target_field = parts[0].strip()
        query = parts[1].strip()

    if not query:
        return list(records)

    query_lower = query.lower()
    result: list[dict] = []
    for record in records:
        search_fields = [target_field] if target_field else fields
        for f in search_fields:
            val = record.get(f)
            if val is not None and query_lower in str(val).lower():
                result.append(record)
                break

    return result
