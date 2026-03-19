"""Splunk indexes router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api.splunk_auth import require_splunk_auth
from application.splunk.queries.indexes import get_index, list_indexes
from domain.splunk.splunk_index import SplunkIndex
from repository.splunk.splunk_index_repo import splunk_index_repo

router = APIRouter(tags=["Splunk Indexes"])


@router.get("/services/data/indexes")
def list_all_indexes(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all indexes."""
    return list_indexes()


@router.post("/services/data/indexes")
async def create_index(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Create a new index."""
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        name = str(form.get("name", ""))
    else:
        try:
            body = await request.json()
            name = body.get("name", "")
        except Exception:
            name = ""

    if not name:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Index name is required"},
        ]})

    idx = SplunkIndex(name=name)
    splunk_index_repo.save(idx)
    result = get_index(name)
    return result or {}


@router.get("/services/data/indexes/{name}")
def get_single_index(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a specific index."""
    result = get_index(name)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Index '{name}' not found"},
        ]})
    return result
