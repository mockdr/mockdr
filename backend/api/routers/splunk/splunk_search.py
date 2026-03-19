"""Splunk search jobs router.

Implements the full async search job lifecycle used by XSOAR SplunkPy.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.splunk_auth import require_splunk_auth
from application.splunk.commands.search import (
    cancel_search_job,
    create_search_job,
    delete_search_job,
)
from application.splunk.queries.search import (
    get_events,
    get_job,
    get_results,
    get_summary,
    get_timeline,
    list_jobs,
)

router = APIRouter(tags=["Splunk Search"])


@router.post("/services/search/jobs")
async def create_job(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Create a new search job.

    Accepts form-encoded or JSON body with ``search``, ``earliest_time``,
    ``latest_time``, ``exec_mode``.
    """
    # Parse form or JSON body
    search = ""
    earliest_time = ""
    latest_time = ""
    exec_mode = "normal"

    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        search = str(form.get("search", ""))
        earliest_time = str(form.get("earliest_time", ""))
        latest_time = str(form.get("latest_time", ""))
        exec_mode = str(form.get("exec_mode", "normal"))
    else:
        try:
            body = await request.json()
            search = body.get("search", "")
            earliest_time = body.get("earliest_time", "")
            latest_time = body.get("latest_time", "")
            exec_mode = body.get("exec_mode", "normal")
        except Exception:
            pass

    if not search:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Search query is required"},
        ]})

    sid = create_search_job(
        search=search,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode=exec_mode,
    )
    return {"sid": sid}


@router.get("/services/search/jobs")
def list_search_jobs(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all search jobs."""
    return list_jobs()


@router.get("/services/search/jobs/export")
async def export_search(
    request: Request,
    search: str = Query(default=""),
    earliest_time: str = Query(default=""),
    latest_time: str = Query(default=""),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """One-shot blocking search export."""
    if not search:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Search query is required"},
        ]})

    sid = create_search_job(
        search=search,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode="oneshot",
    )
    result = get_results(sid)
    return result or {"results": [], "fields": [], "init_offset": 0, "messages": []}


@router.get("/services/search/jobs/{sid}")
def get_search_job(
    sid: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get search job status."""
    result = get_job(sid)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Search job '{sid}' not found"},
        ]})
    return result


@router.post("/services/search/jobs/{sid}/control")
async def control_job(
    sid: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Control a search job (pause, unpause, cancel, finalize)."""
    content_type = request.headers.get("content-type", "")
    action = ""
    if "form" in content_type:
        form = await request.form()
        action = str(form.get("action", ""))
    else:
        try:
            body = await request.json()
            action = body.get("action", "")
        except Exception:
            pass

    if action == "cancel":
        cancel_search_job(sid)
    return {"messages": [{"type": "INFO", "text": f"Action '{action}' applied to job '{sid}'"}]}


@router.get("/services/search/v2/jobs/{sid}/results")
def get_job_results(
    sid: str,
    count: int = Query(default=100),
    offset: int = Query(default=0),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get transformed search results."""
    count = min(count, 10_000)
    result = get_results(sid, count, offset)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Search job '{sid}' not found"},
        ]})
    return result


@router.get("/services/search/v2/jobs/{sid}/events")
def get_job_events(
    sid: str,
    count: int = Query(default=100),
    offset: int = Query(default=0),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get raw events from search job."""
    count = min(count, 10_000)
    result = get_events(sid, count, offset)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Search job '{sid}' not found"},
        ]})
    return result


@router.get("/services/search/jobs/{sid}/summary")
def get_job_summary(
    sid: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get field summary for a search job."""
    result = get_summary(sid)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Search job '{sid}' not found"},
        ]})
    return result


@router.get("/services/search/jobs/{sid}/timeline")
def get_job_timeline(
    sid: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get timeline data for a search job."""
    result = get_timeline(sid)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Search job '{sid}' not found"},
        ]})
    return result


@router.delete("/services/search/jobs/{sid}")
def delete_job(
    sid: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Delete a search job."""
    if not delete_search_job(sid):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Search job '{sid}' not found"},
        ]})
    return {"messages": [{"type": "INFO", "text": f"Search job '{sid}' deleted"}]}
