"""Elasticsearch REST API router.

Implements core Elasticsearch endpoints (search, get, mapping, stats)
mounted at ``/elastic``.  These are the endpoints that SOAR integrations
use when configured to talk directly to Elasticsearch.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.es_auth import require_es_auth, require_es_write
from application.es_search import queries as search_queries

router = APIRouter(tags=["ES Search"])


# ── Cluster Info ─────────────────────────────────────────────────────────────


@router.get("/")
def cluster_info(
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return Elasticsearch cluster info."""
    return search_queries.cluster_info()


# ── Search ───────────────────────────────────────────────────────────────────


@router.post("/{index}/_search")
def es_search(
    index: str,
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Execute an Elasticsearch query DSL search against a mock index."""
    return search_queries.es_search(index, body)


# ── Mapping / Stats ──────────────────────────────────────────────────────────


@router.get("/{index}/_mapping")
def get_mapping(
    index: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return the index mapping for a known index pattern."""
    return search_queries.es_get_mapping(index)


@router.get("/{index}/_stats")
def get_stats(
    index: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return index stats for a known index pattern."""
    return search_queries.es_get_stats(index)


# ── Document CRUD ────────────────────────────────────────────────────────────


@router.get("/{index}/_doc/{doc_id}")
def get_doc(
    index: str,
    doc_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single document by ID."""
    result = search_queries.es_get_doc(index, doc_id)
    if result is None:
        return {
            "_index": index,
            "_id": doc_id,
            "found": False,
        }
    return result


@router.post("/{index}/_doc/{doc_id}")
def index_doc(
    index: str,
    doc_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Index (create) a document.

    This is a simplified mock — it acknowledges the write but does not
    persist the document into any backing collection.
    """
    return {
        "_index": index,
        "_id": doc_id,
        "_version": 1,
        "result": "created",
        "_shards": {"total": 2, "successful": 1, "failed": 0},
        "_seq_no": 0,
        "_primary_term": 1,
    }
