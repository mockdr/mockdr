"""Elastic Security API response envelope builders.

Elastic Security uses two distinct response formats:

* **Elasticsearch _search** — ``hits`` envelope with ``took``, ``_shards``, etc.
* **Kibana list** — simple ``page``/``per_page``/``total``/``data`` envelope.
"""
from __future__ import annotations


def build_es_search_response(
    hits: list[dict],
    total: int,
    took: int = 5,
) -> dict:
    """Build an Elasticsearch ``_search`` response envelope.

    Args:
        hits:  List of hit documents to include.
        total: Total number of matching documents.
        took:  Simulated query time in milliseconds.

    Returns:
        Complete Elasticsearch search response envelope.
    """
    return {
        "took": took,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": total, "relation": "eq"},
            "max_score": 1.0 if hits else None,
            "hits": hits,
        },
    }


def build_kibana_list_response(
    data: list,
    page: int,
    per_page: int,
    total: int,
) -> dict:
    """Build a Kibana paginated list response.

    Args:
        data:     Page of resource objects to include.
        page:     Current page number (1-based).
        per_page: Number of items per page.
        total:    Total number of matching resources.

    Returns:
        Kibana list response envelope.
    """
    return {"page": page, "per_page": per_page, "total": total, "data": data}


def build_es_error_response(
    status_code: int,
    error: str,
    reason: str,
) -> dict:
    """Build an Elasticsearch error response.

    Args:
        status_code: HTTP status code.
        error:       Error type string (e.g. ``security_exception``).
        reason:      Human-readable error description.

    Returns:
        Elasticsearch error response envelope.
    """
    return {
        "error": {
            "root_cause": [{"type": error, "reason": reason}],
            "type": error,
            "reason": reason,
        },
        "status": status_code,
    }
