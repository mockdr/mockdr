"""Elastic Security alert query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.es_alert_repo import es_alert_repo
from utils.es_query import apply_es_query, wrap_as_hits
from utils.es_response import build_es_search_response


def search_alerts(body: dict) -> dict:
    """Search alerts using Elasticsearch query DSL.

    Args:
        body: Elasticsearch ``_search`` request body with ``query``,
              ``sort``, ``from``, ``size``, etc.

    Returns:
        Elasticsearch search response envelope with matching alerts.
    """
    all_records = [asdict(a) for a in es_alert_repo.list_all()]
    total = len(all_records)

    filtered = apply_es_query(all_records, body)
    hits = wrap_as_hits(filtered, index=".siem-signals-default")

    return build_es_search_response(hits, total=total)


def get_alert(alert_id: str) -> dict | None:
    """Get a single alert by its ID.

    Args:
        alert_id: The alert ID to look up.

    Returns:
        Alert dict, or None if not found.
    """
    alert = es_alert_repo.get(alert_id)
    if not alert:
        return None
    return asdict(alert)
