"""Splunk search jobs router.

Implements the full async search job lifecycle used by XSOAR SplunkPy.
"""
from __future__ import annotations

import json
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from api.splunk_auth import require_splunk_auth
from application.splunk.commands.search import (
    apply_control_action,
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

#: splunkd's exact wording, measured against Splunk 10.4.2. A client that
#: string-matches the refusal — and some do, to distinguish "no query" from
#: "bad query" — needs the words splunkd uses, not a paraphrase.
_SEARCH_REQUIRED = (
    "The required 'search' parameter for the Splunk platform REST API "
    "search/jobs endpoint is not specified. Specify the required 'search' "
    "parameter for the POST request on the endpoint and then retry your request."
)

router = APIRouter(tags=["Splunk Search"])


@router.post("/services/search/v2/jobs", response_model=None)
@router.post("/services/search/jobs", response_model=None)
async def create_job(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
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
            {"type": "FATAL", "text": _SEARCH_REQUIRED},
        ]})

    sid = create_search_job(
        search=search,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode=exec_mode,
    )

    if exec_mode == "oneshot":
        # A oneshot search returns the results directly; splunklib enforces
        # this by refusing exec_mode="oneshot" in Jobs.create(). Returning a
        # sid here left the caller polling a job it was never given.
        results = get_results(sid, count=0)
        delete_search_job(sid)
        return JSONResponse(
            status_code=200,
            content=results or _EMPTY_RESULTS,
        )

    # Splunk answers 201 Created, and in XML mode the document is
    # <response><sid>…</sid></response> — splunklib's _load_sid reads
    # `_load_atom(response).response.sid`, which found nothing in the
    # <s:dict> shape the generic renderer produced.
    return JSONResponse(status_code=201, content={"sid": sid})


@router.get("/services/search/v2/jobs")
@router.get("/services/search/jobs")
def list_search_jobs(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all search jobs."""
    return list_jobs()


# One decorator per method: an api_route with two methods emits two OpenAPI
# operations under one id, which a client generator rejects as a duplicate.
@router.get(
    "/services/search/v2/jobs/export", response_model=None, operation_id="splunk_export_v2_get",
)
@router.post(
    "/services/search/v2/jobs/export", response_model=None, operation_id="splunk_export_v2_post",
)
@router.get(
    "/services/search/jobs/export", response_model=None, operation_id="splunk_export_get",
)
@router.post(
    "/services/search/jobs/export", response_model=None, operation_id="splunk_export_post",
)
async def export_search(
    request: Request,
    search: str = Query(default=""),
    earliest_time: str = Query(default=""),
    latest_time: str = Query(default=""),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> Response:
    """One-shot blocking search export."""
    # splunklib's Jobs.export() POSTs its parameters as a form; this route
    # took GET only, and the 405 it answered with told the client to fix
    # "the POST request" it had just made.
    if request.method == "POST":
        form = await request.form()
        search = search or str(form.get("search", ""))
        earliest_time = earliest_time or str(form.get("earliest_time", ""))
        latest_time = latest_time or str(form.get("latest_time", ""))
    if not search:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": _SEARCH_REQUIRED},
        ]})

    sid = create_search_job(
        search=search,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode="oneshot",
    )
    result = get_results(sid, count=0) or _EMPTY_RESULTS
    delete_search_job(sid)

    if output_mode.lower() == "json":
        # Real /export streams one JSON object per line, each carrying
        # `preview` and `offset`; splunklib.results.JSONResultsReader is built
        # around that and asserts `is_preview is False`. A single envelope with
        # no `preview` key left is_preview as None.
        return StreamingResponse(
            _export_lines(result),
            media_type="application/json",
        )
    return JSONResponse(status_code=200, content=result)


_EMPTY_RESULTS: dict = {"results": [], "fields": [], "init_offset": 0, "messages": []}


def _export_lines(result: dict) -> Iterator[str]:
    """Yield the newline-delimited objects real ``/export`` streams."""
    for offset, row in enumerate(result.get("results", [])):
        yield json.dumps({"preview": False, "offset": offset, "result": row}) + "\n"


@router.get("/services/search/v2/jobs/{sid}")
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
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.post("/services/search/v2/jobs/{sid}/control")
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

    # Control on a job that does not exist is a 404, not a cheerful 200.
    if get_job(sid) is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})

    if action not in _CONTROL_ACTIONS:
        # Every action, including outright garbage, used to return 200 — so a
        # typo in a playbook looked like it had worked.
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": f"Unknown action '{action}'."},
        ]})

    apply_control_action(sid, action)
    return {
        "messages": [
            {"type": "INFO", "text": f"Action '{action}' applied to job '{sid}'"},
        ],
    }


# The actions splunkd accepts on a search job.
_CONTROL_ACTIONS = frozenset({
    "cancel", "pause", "unpause", "finalize", "touch", "setttl",
    "setpriority", "save", "unsave", "enablepreview", "disablepreview",
})


@router.get("/services/search/v2/jobs/{sid}/results", operation_id="splunk_results_v2_get")
@router.post("/services/search/v2/jobs/{sid}/results", operation_id="splunk_results_v2_post")
@router.get("/services/search/jobs/{sid}/results", operation_id="splunk_results_v1_get")
@router.post("/services/search/jobs/{sid}/results", operation_id="splunk_results_v1_post")
def get_job_results(
    sid: str,
    count: int = Query(default=100),
    offset: int = Query(default=0),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get transformed search results."""
    count = min(count, 10_000) if count > 0 else 0
    result = get_results(sid, count, offset)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.get("/services/search/v2/jobs/{sid}/events", operation_id="splunk_events_v2_get")
@router.post("/services/search/v2/jobs/{sid}/events", operation_id="splunk_events_v2_post")
@router.get("/services/search/jobs/{sid}/events", operation_id="splunk_events_v1_get")
@router.post("/services/search/jobs/{sid}/events", operation_id="splunk_events_v1_post")
def get_job_events(
    sid: str,
    count: int = Query(default=100),
    offset: int = Query(default=0),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get raw events from search job."""
    count = min(count, 10_000) if count > 0 else 0
    result = get_events(sid, count, offset)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.get("/services/search/v2/jobs/{sid}/summary")
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
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.get("/services/search/v2/jobs/{sid}/timeline")
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
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.delete("/services/search/v2/jobs/{sid}")
@router.delete("/services/search/jobs/{sid}")
def delete_job(
    sid: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Delete a search job."""
    if not delete_search_job(sid):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return {"messages": [{"type": "INFO", "text": f"Search job '{sid}' deleted"}]}
