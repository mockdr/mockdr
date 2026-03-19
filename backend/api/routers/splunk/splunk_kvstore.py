"""Splunk KV Store router."""
from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_splunk_auth
from application.splunk.commands.kvstore import (
    batch_save,
    create_collection,
    delete_all_records,
    delete_collection,
    delete_record,
    insert_record,
    update_record,
)
from application.splunk.queries.kvstore import get_record, get_records, list_collections

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
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Create a KV Store collection."""
    body = await _parse_body(request)
    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Collection name is required"},
        ]})
    coll = create_collection(name, app, owner)
    return {"name": coll.name}


@router.delete("/servicesNS/{owner}/{app}/storage/collections/config/{name}")
def delete_kv_collection(
    owner: str,
    app: str,
    name: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Delete a KV Store collection."""
    if not delete_collection(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Collection '{name}' not found"},
        ]})
    return {"messages": [{"type": "INFO", "text": f"Collection '{name}' deleted"}]}


# ── Collection data ────────────────────────────────────────────────────────

@router.get("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
def get_all_records(
    owner: str,
    app: str,
    name: str,
    current_user: dict = Depends(require_splunk_auth),
) -> list[dict]:
    """Get all records from a KV collection."""
    return get_records(name, app)


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
async def insert_kv_record(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Insert a record into a KV collection."""
    body = await request.json()
    result = insert_record(name, body, app)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Collection '{name}' not found"},
        ]})
    return result


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
    return batch_save(name, records, app)


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
            {"type": "ERROR", "text": f"Collection '{name}' not found"},
        ]})
    return JSONResponse(status_code=200, content={})


async def _parse_body(request: Request) -> dict:
    """Parse request body from form or JSON."""
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        return {k: str(v) for k, v in form.items()}
    try:
        return cast(dict[str, Any], await request.json())
    except Exception:
        return {}
