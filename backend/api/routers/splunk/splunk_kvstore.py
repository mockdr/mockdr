"""Splunk KV Store router."""
from __future__ import annotations

import json
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_splunk_admin, require_splunk_auth
from application.splunk.commands.kvstore import (
    DuplicateKeyError,
    batch_save,
    create_collection,
    delete_all_records,
    delete_collection,
    delete_record,
    insert_record,
    update_record,
)
from application.splunk.queries.kvstore import (
    collection_exists,
    get_record,
    get_records,
    list_collections,
)

router = APIRouter(tags=["Splunk KV Store"])


# ── Collection config ──────────────────────────────────────────────────────

@router.get("/servicesNS/{owner}/{app}/storage/collections/config")
def list_kv_collections(
    owner: str,
    app: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List KV Store collections."""
    return list_collections(app)


@router.post("/servicesNS/{owner}/{app}/storage/collections/config")
async def create_kv_collection(
    owner: str,
    app: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Create a KV Store collection."""
    body = await _parse_body(request)
    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR",
             "text": 'Cannot perform action "POST" without a target name to act on.'},
        ]})
    coll = create_collection(name, app, owner)
    return {"name": coll.name}


@router.delete("/servicesNS/{owner}/{app}/storage/collections/config/{name}")
def delete_kv_collection(
    owner: str,
    app: str,
    name: str,
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Delete a KV Store collection."""
    if not delete_collection(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return {"messages": [{"type": "INFO", "text": f"Collection '{name}' deleted"}]}


# ── Collection data ────────────────────────────────────────────────────────

@router.get("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
def get_all_records(
    owner: str,
    app: str,
    name: str,
    query: str = Query(default=""),
    fields: str = Query(default=""),
    sort: str = Query(default=""),
    limit: int = Query(default=0),
    skip: int = Query(default=0),
    current_user: dict = Depends(require_splunk_auth),
) -> list[dict]:
    """Get records from a KV collection.

    ``query``, ``fields``, ``sort``, ``limit`` and ``skip`` are all documented
    on this endpoint and are what splunklib's ``query()`` sends; none were
    declared here, so every one was dropped and the whole collection came back.
    """
    if not collection_exists(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return get_records(
        name, app, query=query, fields=fields, sort=sort, limit=limit, skip=skip,
    )


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
async def insert_kv_record(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Insert a record into a KV collection.

    Real Splunk answers 201 with only the new document key, and rejects a
    duplicate ``_key`` with 409 — this used to return 200 with the whole
    record and append a second copy under the same key.
    """
    body = await request.json()
    try:
        result = insert_record(name, body, app)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail={"messages": [
            {"type": "ERROR", "text": str(exc)},
        ]}) from exc
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return JSONResponse(status_code=201, content={"_key": result["_key"]})


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}/batch_save")
async def batch_save_records(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> list[dict]:
    """Batch upsert records into a KV collection."""
    records = await request.json()
    if not isinstance(records, list):
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Expected a JSON array of records"},
        ]})
    saved = batch_save(name, records, app)
    # Splunk returns the keys, not the documents.
    return [{"_key": r["_key"]} for r in saved]


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}/batch_find")
async def batch_find_records(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> list[list[dict]]:
    """Run several KV Store queries in one request.

    splunklib's ``KVStoreCollectionData.batch_find`` posts an array of query
    objects and reads back one result array per query; the route was absent.
    """
    if not collection_exists(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})

    queries = await request.json()
    if not isinstance(queries, list):
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Expected a JSON array of query objects"},
        ]})

    return [
        get_records(name, app, query=json.dumps(q) if isinstance(q, dict) else "")
        for q in queries
    ]


@router.get("/servicesNS/{owner}/{app}/storage/collections/data/{name}/{key}")
def get_kv_record(
    owner: str,
    app: str,
    name: str,
    key: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a single record from a KV collection."""
    result = get_record(name, key, app)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Record '{key}' not found"},
        ]})
    return result


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}/{key}")
async def update_kv_record(
    owner: str,
    app: str,
    name: str,
    key: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Update a record in a KV collection."""
    body = await request.json()
    result = update_record(name, key, body, app)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Record '{key}' not found"},
        ]})
    return result


@router.delete("/servicesNS/{owner}/{app}/storage/collections/data/{name}/{key}")
def delete_kv_record(
    owner: str,
    app: str,
    name: str,
    key: str,
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Delete a record from a KV collection."""
    if not delete_record(name, key, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Record '{key}' not found"},
        ]})
    return JSONResponse(status_code=200, content={})


@router.delete("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
def delete_all_kv_records(
    owner: str,
    app: str,
    name: str,
    query: str = Query(default=""),
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Delete all records from a KV collection."""
    if not delete_all_records(name, app, query):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return JSONResponse(status_code=200, content={})


async def _parse_body(request: Request) -> dict:
    """Parse request body from form or JSON."""
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        return {k: str(v) for k, v in form.items()}
    try:
        parsed = await request.json()
    except Exception:
        return {}
    # A JSON `null` or array is not a parameter set; treating it as an empty
    # one lets the route report the parameter it needed, instead of 500.
    return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
