"""Splunk search jobs router.

Implements the full async search job lifecycle used by XSOAR SplunkPy.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from api.reserved_names import register as _register_convertors
from api.splunk_auth import require_splunk_auth
from application.splunk.commands.search import (
    SAVED_TTL,
    InvalidTimeParameterError,
    UnknownSearchCommandError,
    apply_control_action,
    control_message,
    create_search_job,
    delete_search_job,
)
from application.splunk.queries.search import (
    SearchJobFailedError,
    get_events,
    get_job,
    get_results,
    get_summary,
    get_timeline,
    list_jobs,
)
from repository.splunk.splunk_event_repo import splunk_event_repo
from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.csv_output import render_splunk_csv
from utils.splunk.spl_parser import resolve_relative_time
from utils.splunk.xml_output import render_splunk_xml

#: splunkd's exact wording, measured against Splunk 10.4.2. A client that
#: string-matches the refusal — and some do, to distinguish "no query" from
#: "bad query" — needs the words splunkd uses, not a paraphrase.
_SEARCH_REQUIRED = (
    "The required 'search' parameter for the Splunk platform REST API "
    "search/jobs endpoint is not specified. Specify the required 'search' "
    "parameter for the POST request on the endpoint and then retry your request."
)

_register_convertors()

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

    # What the client actually sent, which the job echoes back as `request`:
    # splunkd repeats those arguments and no others, and mockdr answered a
    # recorded fixture's arguments instead — every job reported having been
    # dispatched with a query no client had ever sent.
    dispatched: dict[str, str] = {}

    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        dispatched = {k: str(v) for k, v in form.items() if isinstance(v, str)}
        search = str(form.get("search", ""))
        earliest_time = str(form.get("earliest_time", ""))
        latest_time = str(form.get("latest_time", ""))
        exec_mode = str(form.get("exec_mode", "normal"))
    else:
        try:
            body = await request.json()
            dispatched = {k: str(v) for k, v in body.items()}
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

    try:
        sid = create_search_job(
            search=search,
            earliest_time=earliest_time,
            latest_time=latest_time,
            exec_mode=exec_mode,
            request={k: v for k, v in dispatched.items() if k != "output_mode"},
        )
    except (InvalidTimeParameterError, UnknownSearchCommandError) as exc:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": str(exc)},
        ]}) from exc

    if exec_mode == "oneshot":
        # A oneshot search returns the results directly; splunklib enforces
        # this by refusing exec_mode="oneshot" in Jobs.create(). Returning a
        # sid here left the caller polling a job it was never given.
        try:
            results = get_results(sid, count=0)
        except SearchJobFailedError as exc:
            # A search that could not run answers 200 with the messages alone
            # — no `results`, no `fields`, nothing that reads as an answer.
            delete_search_job(sid)
            return JSONResponse(status_code=200, content={"messages": exc.messages})
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
#
# POST only: splunkd answers 405 `Allow: POST` to a GET here, whatever query
# string it carries (measured on 10.4.2). Serving GET as well did no harm on
# its own and put GET in the `Allow` of every *other* verb's refusal, which
# is how a route nobody has claims to exist.
@router.post(
    "/services/search/v2/jobs/export", response_model=None, operation_id="splunk_export_v2_post",
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
        # splunklib posts every parameter as a form, `output_mode` included;
        # reading it from the query string alone streamed json whatever the
        # client asked for.
        if "output_mode" not in request.query_params:
            output_mode = str(form.get("output_mode", output_mode))
    if not search:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": _SEARCH_REQUIRED},
        ]})

    try:
        sid = create_search_job(
            search=search,
            earliest_time=earliest_time,
            latest_time=latest_time,
            exec_mode="oneshot",
        )
    except (InvalidTimeParameterError, UnknownSearchCommandError) as exc:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": str(exc)},
        ]}) from exc
    try:
        result = get_results(sid, count=0) or _EMPTY_RESULTS
    except SearchJobFailedError as exc:
        delete_search_job(sid)
        raise HTTPException(
            status_code=400, detail={"messages": exc.messages},
        ) from exc
    delete_search_job(sid)

    mode = output_mode.lower()
    if mode == "json_rows":
        # One document rather than a stream: the fields once, then the rows.
        rows = result.get("results") or []
        names = _field_names(result, rows)
        # splunkd writes this one compactly, and a client comparing bytes
        # against a recorded answer sees the difference.
        return Response(
            content=json.dumps({
                "preview": False,
                "init_offset": 0,
                "messages": result.get("messages") or [],
                "fields": names,
                "rows": [[_cell(row.get(name)) for name in names] for row in rows],
            }, separators=(",", ":")),
            media_type="application/json; charset=UTF-8",
        )
    if mode == "csv":
        return Response(
            content=render_splunk_csv(result),
            media_type="text/csv; charset=UTF-8",
        )
    if mode == "xml":
        # The export document has no blank line under its declaration, where
        # a job's results do (both measured).
        return Response(
            content=render_splunk_xml(result).replace("?>\n\n", "?>\n", 1),
            media_type="text/xml; charset=UTF-8",
        )
    # Real /export streams one JSON object per line, each carrying `preview`
    # and `offset`; splunklib.results.JSONResultsReader is built around that
    # and asserts `is_preview is False`. A single envelope with no `preview`
    # key left is_preview as None.
    return StreamingResponse(_export_lines(result), media_type="application/json")


def _field_names(result: dict, rows: list) -> list[str]:
    """The columns an export names, declared order first."""
    declared = [
        str(field.get("name")) for field in result.get("fields") or []
        if isinstance(field, dict) and field.get("name")
    ]
    return declared or list(dict.fromkeys(key for row in rows for key in row))


def _cell(value: object) -> object:
    """One cell of a `json_rows` export: a multivalue field keeps its list."""
    return value if isinstance(value, (list, str, type(None))) else str(value)


#: The envelope splunkd sends when a search produced no rows: no `fields`
#: and no `highlighted`, a `post_process_count` instead, and `preview` always
#: present (measured against Splunk 10).
_EMPTY_RESULTS: dict = {
    "preview": False,
    "init_offset": 0,
    "messages": [],
    "results": [],
    "post_process_count": 0,
}


def _export_lines(result: dict) -> Iterator[str]:
    """Yield the newline-delimited objects real ``/export`` streams.

    The last row says so, and a search with no rows at all is one line
    saying only that — which is how a client knows the stream ended rather
    than broke. mockdr sent nothing for an empty search, and never marked
    the end of a full one.
    """
    rows = result.get("results") or []
    if not rows:
        yield json.dumps({"preview": False, "lastrow": True}, separators=(",", ":")) + "\n"
        return
    for offset, row in enumerate(rows):
        line: dict = {"preview": False, "offset": offset}
        if offset == len(rows) - 1:
            line["lastrow"] = True
        line["result"] = row
        yield json.dumps(line, separators=(",", ":")) + "\n"


@router.get("/services/search/v2/jobs/{sid:splunksid}")
@router.get("/services/search/jobs/{sid:splunksid}")
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


@router.post("/services/search/v2/jobs/{sid:splunksid}/control")
@router.post("/services/search/jobs/{sid:splunksid}/control")
async def control_job(
    sid: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Control a search job (pause, unpause, cancel, finalize)."""
    content_type = request.headers.get("content-type", "")
    action = ""
    form_values: dict[str, str] = {}
    if "form" in content_type:
        form = await request.form()
        form_values = {k: str(v) for k, v in form.items()}
    else:
        try:
            body = await request.json()
            form_values = {k: str(v) for k, v in body.items()} if isinstance(body, dict) else {}
        except Exception:
            pass
    action = form_values.get("action", "")

    # Control on a job that does not exist is a 404, not a cheerful 200.
    if get_job(sid) is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})

    if action not in _CONTROL_ACTIONS:
        # Every action, including outright garbage, used to return 200 — so a
        # typo in a playbook looked like it had worked. splunkd names neither
        # the action nor the job: "Unknown action.", FATAL (measured).
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": "Unknown action."},
        ]})

    ttl = _requested_ttl(form_values, action)
    apply_control_action(sid, action, ttl)
    return {
        "messages": [
            {"type": "INFO", "text": control_message(action, ttl)},
        ],
    }


def _requested_ttl(values: dict[str, str], action: str) -> int:
    """The ttl this control call sets, in the seconds splunkd reports back."""
    if action == "save":
        return SAVED_TTL
    try:
        return int(values.get("ttl", ""))
    except ValueError:
        return 0


# The actions splunkd accepts on a search job.
_CONTROL_ACTIONS = frozenset({
    "cancel", "pause", "unpause", "finalize", "touch", "setttl",
    "setpriority", "save", "unsave", "enablepreview", "disablepreview",
})


@router.get(
    "/services/search/v2/jobs/{sid:splunksid}/results",
    operation_id="splunk_results_v2_get",
)
@router.post(
    "/services/search/v2/jobs/{sid:splunksid}/results",
    operation_id="splunk_results_v2_post",
)
@router.get("/services/search/jobs/{sid:splunksid}/results", operation_id="splunk_results_v1_get")
@router.post("/services/search/jobs/{sid:splunksid}/results", operation_id="splunk_results_v1_post")
def get_job_results(
    sid: str,
    count: int = Query(default=100),
    offset: int = Query(default=0),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get transformed search results."""
    count = min(count, 10_000) if count > 0 else 0
    try:
        result = get_results(sid, count, offset)
    except SearchJobFailedError as exc:
        raise HTTPException(
            status_code=400, detail={"messages": exc.messages},
        ) from exc
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.get("/services/search/v2/jobs/{sid:splunksid}/events", operation_id="splunk_events_v2_get")
@router.post(
    "/services/search/v2/jobs/{sid:splunksid}/events",
    operation_id="splunk_events_v2_post",
)
@router.get("/services/search/jobs/{sid:splunksid}/events", operation_id="splunk_events_v1_get")
@router.post("/services/search/jobs/{sid:splunksid}/events", operation_id="splunk_events_v1_post")
def get_job_events(
    sid: str,
    count: int = Query(default=100),
    offset: int = Query(default=0),
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get raw events from search job."""
    count = min(count, 10_000) if count > 0 else 0
    try:
        result = get_events(sid, count, offset)
    except SearchJobFailedError as exc:
        raise HTTPException(
            status_code=400, detail={"messages": exc.messages},
        ) from exc
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "FATAL", "text": "Unknown sid."},
        ]})
    return result


@router.get("/services/search/v2/jobs/{sid:splunksid}/summary")
@router.get("/services/search/jobs/{sid:splunksid}/summary")
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


@router.get("/services/search/v2/jobs/{sid:splunksid}/timeline")
@router.get("/services/search/jobs/{sid:splunksid}/timeline")
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


@router.delete("/services/search/v2/jobs/{sid:splunksid}")
@router.delete("/services/search/jobs/{sid:splunksid}")
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


# ── Time and typeahead ───────────────────────────────────────────────────────
#
# Two small endpoints a dashboard and a search bar lean on, both 404 here:
# `timeparser` resolves a time modifier so a client can show the window it is
# about to search, and `typeahead` completes a term from what the index
# actually holds. Measured on 10.4.2, refusals included.

@router.get("/services/search/timeparser")
def timeparser(
    request: Request,
    time: str = Query(default="now"),
    _user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Resolve a time modifier to the instant it stands for.

    The answer is keyed by the modifier itself, so a client that asked about
    several gets them back by name. splunkd takes one at a time: a repeated
    parameter, or a modifier it cannot read, is `Invalid time.`
    """
    modifiers = request.query_params.getlist("time") or [time]
    if len(modifiers) != 1:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": _INVALID_TIME},
        ]})
    resolved = resolve_relative_time(modifiers[0])
    if not resolved:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "FATAL", "text": _INVALID_TIME},
        ]})
    moment = datetime.fromtimestamp(resolved, tz=UTC)
    return JSONResponse(status_code=200, content={
        modifiers[0]: moment.strftime("%Y-%m-%dT%H:%M:%S.") +
        f"{moment.microsecond // 1000:03d}+00:00",
    })


_INVALID_TIME = "Invalid time."

#: The four fields typeahead completes from the events themselves. splunkd
#: marks an index as an `operator` and the rest not — the flag a search bar
#: uses to decide how to render the suggestion.
_TYPEAHEAD_FIELDS = ("index", "sourcetype", "source", "host")


@router.get("/services/search/typeahead")
def typeahead(
    prefix: str = Query(default=""),
    count: int = Query(default=50, ge=0),
    _user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Complete a search term from what the events actually carry."""
    field, _, written = prefix.partition("=")
    if not _ or field not in _TYPEAHEAD_FIELDS:
        # splunkd completes a `field=` term and nothing else: a bare word or
        # a pipe gets an empty list rather than a guess.
        return JSONResponse(status_code=200, content={"results": []})

    wanted = written.strip('"')
    counts: Counter[str] = Counter()
    for event in splunk_event_repo.list_all():
        value = str(getattr(event, field, "") or "")
        if value and value.startswith(wanted):
            counts[value] += 1
    if field == "index":
        # Every index is offered, even one nothing has been written to.
        for index in splunk_index_repo.list_all():
            if index.name.startswith(wanted):
                counts.setdefault(index.name, 0)
    return JSONResponse(status_code=200, content={"results": [
        {"content": f'{field}="{value}"', "count": counts[value] if field != "index" else 0,
         "operator": field == "index"}
        for value in sorted(counts)[:count]
    ]})
