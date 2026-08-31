"""Elastic Security alert query handlers (read-only)."""
from __future__ import annotations

from repository.es_alert_repo import es_alert_repo
from utils.es_ecs import to_ecs_document
from utils.es_query import apply_es_query, apply_source_filter, filter_es_records, wrap_as_hits
from utils.es_response import build_es_search_response
from utils.serde import record_dict


def search_alerts(body: dict) -> dict:
    """Search alerts using Elasticsearch query DSL.

    Args:
        body: Elasticsearch ``_search`` request body with ``query``,
              ``sort``, ``from``, ``size``, etc.

    Returns:
        Elasticsearch search response envelope with matching alerts.
    """
    index = ".siem-signals-default"
    all_records = [
        to_ecs_document(record_dict(a), index) for a in es_alert_repo.list_all()
    ]
    # What the query matched, not how many alerts exist: `hits.total.value`
    # answered the index size for every filter, so a client counting matches
    # with `size: 0` — which is how a triage view counts — got the same
    # number whatever it asked. Measured on 8.15: a `term` query over four
    # documents reports 3 and 1, never 4.
    total = len(filter_es_records(all_records, body))

    filtered = apply_es_query(all_records, body)
    hits = apply_source_filter(
        wrap_as_hits(filtered, index=index), body.get("_source"),
    )

    return build_es_search_response(hits, total=total)
