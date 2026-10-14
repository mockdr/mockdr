"""Elastic Security alert query handlers (read-only)."""
from __future__ import annotations

from application.es_search.queries import es_search

#: The alerts-as-data index Kibana 8.15 searches for the default space —
#: `ruleDataClient.indexNameWithNamespace(spaceId)`. mockdr serves the
#: default space only (see `api/middleware/kibana_space.py`).
ALERTS_INDEX = ".alerts-security.alerts-default"

#: What `query_signals_route.ts` (kibana v8.15.0) takes from the body and
#: hands to Elasticsearch, and nothing else: `from` and `search_after` are
#: not among them, so a request carrying them gets the first page.
PASSED_THROUGH = ("query", "aggs", "_source", "fields", "track_total_hits",
                  "size", "runtime_mappings", "sort")

#: The members whose absence together the route refuses — every one of the
#: above but `runtime_mappings`.
REQUIRED_ONE_OF = ("query", "aggs", "_source", "fields", "track_total_hits",
                   "size", "sort")


def search_alerts(body: dict) -> dict:
    """Search the alerts the way `POST /api/detection_engine/signals/search` does.

    The route is a thin pass-through: it picks eight members out of the
    body and runs them as an Elasticsearch search over the space's alerts
    index with `ignore_unavailable: true`, answering the cluster's response
    as it came — aggregations, `total.relation` and all. mockdr searched
    the legacy `.siem-signals-default` with `signal.*` documents, dropped
    `aggs`, and always reported an exact total.

    Args:
        body: The request body, already checked to carry one of
              :data:`REQUIRED_ONE_OF`.

    Returns:
        The Elasticsearch search response.
    """
    search_body = {key: body[key] for key in PASSED_THROUGH if body.get(key) is not None}
    return es_search(ALERTS_INDEX, search_body, ignore_unavailable=True)
