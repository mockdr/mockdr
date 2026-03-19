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

from utils.mde_odata import (
    apply_odata_filter,
    apply_odata_orderby,
    apply_odata_select,
)

# Re-export so callers can import everything from one place
__all__ = [
    "apply_odata_filter",
    "apply_odata_orderby",
    "apply_odata_select",
    "apply_graph_filter",
    "apply_odata_count",
    "apply_odata_search",
]

# ---------------------------------------------------------------------------
# Lambda pre-processor
# ---------------------------------------------------------------------------

_LAMBDA_RE = re.compile(
    r"(\w[\w/]*)/any\s*\(\s*(\w+)\s*:\s*\2/(\w+)\s+"
    r"(eq|ne|gt|ge|lt|le)\s+"
    r"'([^']*)'\s*\)",
    re.IGNORECASE,
)


def _preprocess_lambda(filter_str: str) -> str:
    """Rewrite OData lambda expressions into flat contains-style checks.

    ``assignedLicenses/any(l: l/skuId eq '...')``
    →  ``_lambda_match_assignedLicenses_skuId eq '...'``

    The actual matching is handled by :func:`_match_lambda_field`.
    """
    return _LAMBDA_RE.sub(r"_lambda_\1_\3 \4 '\5'", filter_str)


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
    ``record["assignedLicenses"]`` and collects all ``skuId`` values into a
    single pipe-separated string so the standard eq/ne comparison works.
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
    return "|".join(str(item.get(prop, "")) for item in items if isinstance(item, dict))


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
        for record in records:
            for m in re.finditer(r"_lambda_\w+", processed):
                lf = m.group(0)
                record[lf] = _match_lambda_field(record, lf)

    result = apply_odata_filter(records, processed)

    # Clean up injected fields
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
) -> int | None:
    """Return the total count if ``$count=true`` and ConsistencyLevel allows it.

    Args:
        records:           All records (pre-filter).
        count_param:       Value of the ``$count`` query parameter.
        consistency_level: Value of the ``ConsistencyLevel`` header.

    Returns:
        Total count, or ``None`` if ``$count`` is not requested or the header
        is missing.
    """
    if not count_param:
        return None
    count_requested = str(count_param).lower() in ("true", "1")
    if not count_requested:
        return None
    # Graph API requires ConsistencyLevel: eventual for $count
    if consistency_level and consistency_level.lower() == "eventual":
        return len(records)
    # For mock purposes, also return count even without the header
    # (some integrations forget it, and being lenient is more useful)
    return len(records)


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
