"""Splunk indexes router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_splunk_admin, require_splunk_auth
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


@router.post("/services/data/indexes", response_model=None)
async def create_index(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> JSONResponse:
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

    if get_index(name):
        # Splunk refuses a duplicate name rather than silently replacing the
        # existing index and its event count.
        raise HTTPException(status_code=409, detail={"messages": [
            {"type": "ERROR", "text": f"Index '{name}' already exists"},
        ]})

    idx = SplunkIndex(name=name)
    splunk_index_repo.save(idx)
    return JSONResponse(status_code=201, content=get_index(name) or {})


@router.delete("/services/data/indexes/{name}")
def delete_index(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Delete an index.

    Real Splunk supports this; the route was absent, so DELETE returned 405.
    """
    if not get_index(name):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Index '{name}' not found"},
        ]})
    splunk_index_repo.delete(name)
    return {"messages": [{"type": "INFO", "text": f"Index '{name}' deleted"}]}


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
