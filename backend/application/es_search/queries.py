"""Elasticsearch REST API query handlers for the mock server.

Routes search requests to the appropriate in-memory collection based on the
index pattern, applies Elasticsearch query DSL, and returns standard ES
response envelopes.
"""
from __future__ import annotations

from dataclasses import asdict

from repository.es_alert_repo import es_alert_repo
from repository.es_endpoint_repo import es_endpoint_repo
from utils.es_query import _build_predicate, apply_es_query, wrap_as_hits
from utils.es_response import build_es_search_response

# ── Index pattern routing ────────────────────────────────────────────────────

def _resolve_collection(index: str) -> tuple[list[dict], str]:
    """Resolve an index pattern to the backing in-memory collection.

    Args:
        index: Elasticsearch index name or pattern.

    Returns:
        Tuple of (records as dicts, canonical index name).
    """
    idx = index.lower()

    if idx.startswith(".siem-signals") or idx.startswith(".alerts-security"):
        records = [asdict(a) for a in es_alert_repo.list_all()]
        return records, idx

    if idx.startswith("metrics-endpoint") or idx.startswith("logs-endpoint"):
        records = [asdict(ep) for ep in es_endpoint_repo.list_all()]
        return records, idx

    return [], idx


# ── Public query functions ───────────────────────────────────────────────────

def es_search(index: str, body: dict) -> dict:
    """Execute an Elasticsearch _search against the mock data.

    Args:
        index: Target index name or pattern.
        body:  Elasticsearch query DSL request body.

    Returns:
        Full Elasticsearch _search response envelope.
    """
    records, canonical_index = _resolve_collection(index)

    # Capture total before pagination.
    total_before = len(records)

    # Apply query DSL (filter, sort, from/size).
    filtered = apply_es_query(records, body)

    # If a query clause was provided, the total is the filtered count
    # before from/size pagination; otherwise it's all records.
    query_clause = body.get("query")
    if query_clause:
        # Re-filter without pagination to get the true total.
        predicate = _build_predicate(query_clause)
        total = sum(1 for r in records if predicate(r))
    else:
        total = total_before

    hits = wrap_as_hits(filtered, index=canonical_index)
    return build_es_search_response(hits, total)


def es_get_doc(index: str, doc_id: str) -> dict | None:
    """Get a single document by ID from the appropriate collection.

    Args:
        index:  Target index name or pattern.
        doc_id: Document ID.

    Returns:
        Elasticsearch get response dict, or None if not found.
    """
    records, canonical_index = _resolve_collection(index)

    for rec in records:
        if rec.get("id") == doc_id:
            return {
                "_index": canonical_index,
                "_id": doc_id,
                "_version": 1,
                "_seq_no": 0,
                "_primary_term": 1,
                "found": True,
                "_source": rec,
            }

    return None


def es_get_mapping(index: str) -> dict:
    """Return a canned index mapping for known index patterns.

    Args:
        index: Target index name or pattern.

    Returns:
        Elasticsearch mapping response dict.
    """
    idx = index.lower()

    if idx.startswith(".siem-signals") or idx.startswith(".alerts-security"):
        properties = {
            "@timestamp": {"type": "date"},
            "signal.rule.id": {"type": "keyword"},
            "signal.rule.name": {"type": "keyword"},
            "signal.status": {"type": "keyword"},
            "kibana.alert.severity": {"type": "keyword"},
            "kibana.alert.workflow_status": {"type": "keyword"},
            "agent.id": {"type": "keyword"},
            "host.name": {"type": "keyword"},
        }
    elif idx.startswith("metrics-endpoint") or idx.startswith("logs-endpoint"):
        properties = {
            "@timestamp": {"type": "date"},
            "agent.id": {"type": "keyword"},
            "agent.status": {"type": "keyword"},
            "host.hostname": {"type": "keyword"},
            "host.os.name": {"type": "keyword"},
            "host.os.platform": {"type": "keyword"},
            "host.ip": {"type": "ip"},
        }
    else:
        properties = {}

    return {
        index: {
            "mappings": {
                "properties": properties,
            },
        },
    }


def es_get_stats(index: str) -> dict:
    """Return canned index stats for known index patterns.

    Args:
        index: Target index name or pattern.

    Returns:
        Elasticsearch index stats response dict.
    """
    records, _ = _resolve_collection(index)
    doc_count = len(records)

    return {
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "_all": {
            "primaries": {
                "docs": {"count": doc_count, "deleted": 0},
                "store": {"size_in_bytes": doc_count * 1024},
            },
            "total": {
                "docs": {"count": doc_count, "deleted": 0},
                "store": {"size_in_bytes": doc_count * 1024},
            },
        },
        "indices": {
            index: {
                "primaries": {
                    "docs": {"count": doc_count, "deleted": 0},
                    "store": {"size_in_bytes": doc_count * 1024},
                },
                "total": {
                    "docs": {"count": doc_count, "deleted": 0},
                    "store": {"size_in_bytes": doc_count * 1024},
                },
            },
        },
    }


def cluster_info() -> dict:
    """Return mock Elasticsearch cluster info (version 8.x).

    Returns:
        Elasticsearch cluster info response dict.
    """
    return {
        "name": "mock-es-node-01",
        "cluster_name": "mockdr-elastic",
        "cluster_uuid": "mock-cluster-uuid-0001",
        "version": {
            "number": "8.12.0",
            "build_flavor": "default",
            "build_type": "docker",
            "build_hash": "abc123mock",
            "build_date": "2024-01-01T00:00:00.000Z",
            "build_snapshot": False,
            "lucene_version": "9.9.1",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }
