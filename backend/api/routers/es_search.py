"""Elasticsearch REST API router.

Implements core Elasticsearch endpoints (search, get, mapping, stats)
mounted at ``/elastic``.  These are the endpoints that SOAR integrations
use when configured to talk directly to Elasticsearch.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response

from api.es_auth import require_es_auth, require_es_write
from application.es_search import queries as search_queries
from application.es_search.queries import IndexNotFoundError, MultipleIndicesError
from utils.es_response import build_es_error_response, build_es_index_not_found

router = APIRouter(tags=["ES Search"])


def _missing_index(exc: IndexNotFoundError) -> HTTPException:
    """Translate a missing index into Elasticsearch's 404."""
    return HTTPException(status_code=404, detail=build_es_index_not_found(exc.index))


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
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Execute an Elasticsearch query DSL search against a mock index."""
    try:
        return search_queries.es_search(index, body, ignore_unavailable=ignore_unavailable)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


# ── Mapping / Stats ──────────────────────────────────────────────────────────


@router.get("/{index}/_mapping")
def get_mapping(
    index: str,
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return the index mapping for a known index pattern."""
    try:
        return search_queries.es_get_mapping(index, ignore_unavailable=ignore_unavailable)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_stats")
def get_stats(
    index: str,
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return index stats for a known index pattern."""
    try:
        return search_queries.es_get_stats(index, ignore_unavailable=ignore_unavailable)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


# ── Document CRUD ────────────────────────────────────────────────────────────


@router.get("/{index}/_doc/{doc_id}")
def get_doc(
    index: str,
    doc_id: str,
    response: Response,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single document by ID.

    A miss is a ``404`` carrying ``found: false`` — not the standard error
    envelope, and not the ``200`` this returned before. Elasticsearch's own
    REST spec test asserts the 404; its API reference documents only the 200,
    which is why the status is easy to get wrong.
    """
    try:
        result = search_queries.es_get_doc(index, doc_id)
    except MultipleIndicesError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "illegal_argument_exception", str(exc)),
        ) from exc
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc

    if result is None:
        response.status_code = 404
        return {"_index": index, "_id": doc_id, "found": False}
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
