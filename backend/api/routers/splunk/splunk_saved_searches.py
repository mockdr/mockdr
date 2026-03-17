"""Splunk saved searches router."""
from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from api.splunk_auth import require_splunk_auth
from application.splunk.commands.saved_search import (
    create_saved_search,
    delete_saved_search,
    dispatch_saved_search,
    update_saved_search,
)
from application.splunk.queries.saved_search import (
    get_dispatch_history,
    get_saved_search,
    list_saved_searches,
)

router = APIRouter(tags=["Splunk Saved Searches"])


@router.get("/services/saved/searches")
def list_searches(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all saved searches."""
    return list_saved_searches()


@router.post("/services/saved/searches")
async def create_search(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Create a new saved search."""
    body = await _parse_body(request)
    name = body.get("name", "")
    search = body.get("search", "")
    if not name or not search:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "name and search are required"},
        ]})

    extra = {k: v for k, v in body.items() if k not in ("name", "search")}
    create_saved_search(name, search, **extra)
    result = get_saved_search(name)
    return result or {}


@router.get("/services/saved/searches/{name}")
def get_search(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a saved search by name."""
    result = get_saved_search(name)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Saved search '{name}' not found"},
        ]})
    return result


@router.post("/services/saved/searches/{name}")
async def update_search(
    name: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Update a saved search."""
    body = await _parse_body(request)
    ss = update_saved_search(name, **body)
    if not ss:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Saved search '{name}' not found"},
        ]})
    result = get_saved_search(name)
    return result or {}


@router.delete("/services/saved/searches/{name}")
def delete_search(
    name: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Delete a saved search."""
    if not delete_saved_search(name):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Saved search '{name}' not found"},
        ]})
    return {"messages": [{"type": "INFO", "text": f"Saved search '{name}' deleted"}]}


@router.post("/services/saved/searches/{name}/dispatch")
def dispatch_search(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Dispatch (run) a saved search."""
    sid = dispatch_saved_search(name)
    if not sid:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Saved search '{name}' not found"},
        ]})
    return {"sid": sid}


@router.get("/services/saved/searches/{name}/history")
def get_history(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get dispatch history for a saved search."""
    result = get_dispatch_history(name)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Saved search '{name}' not found"},
        ]})
    return result


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
