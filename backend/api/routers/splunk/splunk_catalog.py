"""Splunk service-catalogue endpoints.

``/services``, ``/services/apps/local`` and ``/services/messages`` are the
first calls a client makes to discover what a splunkd instance offers, and
``/services/search/parse`` is what ``splunklib``'s ``Service.parse()`` uses to
validate a query without dispatching it. All four returned 404, so a client
probing the instance concluded it was talking to something that was not Splunk.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_splunk_auth
from utils.splunk.response import build_splunk_entry, build_splunk_envelope
from utils.splunk.spl_parser import KNOWN_COMMANDS, parse_spl

router = APIRouter(tags=["Splunk Catalog"])

#: The service paths this instance exposes, as ``/services`` advertises them.
_SERVICES: tuple[tuple[str, str], ...] = (
    ("alerts", "alerts/fired_alerts"),
    ("apps", "apps/local"),
    ("authentication", "authentication/users"),
    ("authorization", "authorization/roles"),
    ("data", "data/indexes"),
    ("messages", "messages"),
    ("saved", "saved/searches"),
    ("search", "search/jobs"),
    ("server", "server/info"),
    ("storage", "storage/collections/config"),
)

#: Content every app entry carries on Splunk 10.4.2 besides its own values.
_APP_COMMON: dict[str, object] = {
    "check_for_updates": True,
    "configured": True,
    "core": True,
    "eai:acl": None,
    "managed_by_deployment_client": False,
    "show_in_nav": True,
    "state_change_requires_restart": False,
}
#: An app's ACL carries four sharing capabilities a generic entry does not.
_APP_ACL: dict[str, object] = {
    "can_change_perms": True, "can_share_app": True,
    "can_share_global": True, "can_share_user": False,
}
_APP_LINKS = ("alternate", "list", "_reload", "edit", "package")
#: Only a single app GET carries `fields`; the list does not.
_APP_FIELDS = {
    "required": [],
    "optional": [
        "author", "check_for_updates", "configured", "description", "label",
        "upload_id", "version", "visible",
    ],
    "wildcard": [],
}

#: Apps a stock Splunk install reports, plus the mockdr-specific one.
_APPS: tuple[dict[str, object], ...] = (
    {
        "name": "search",
        "label": "Search & Reporting",
        "version": "9.4.0",
        "author": "Splunk",
        "description": "The Search & Reporting application",
        "disabled": False,
        "visible": True,
    },
    {
        "name": "splunk_httpinput",
        "label": "Splunk HTTP Input",
        "version": "9.4.0",
        "author": "Splunk",
        "description": "HTTP Event Collector",
        "disabled": False,
        "visible": False,
    },
    {
        "name": "SplunkEnterpriseSecuritySuite",
        "label": "Enterprise Security",
        "version": "7.3.0",
        "author": "Splunk",
        "description": "Splunk Enterprise Security",
        "disabled": False,
        "visible": True,
    },
)


@router.get("/services")
def list_services(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List the service endpoints this instance exposes."""
    entries = [
        build_splunk_entry(name, {"path": path}, collection="services")
        for name, path in _SERVICES
    ]
    return build_splunk_envelope(entries)


@router.get("/services/apps/local")
def list_apps(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List installed apps, which clients read to pick a namespace."""
    entries = [
        build_splunk_entry(
            str(app["name"]), _app_content(app), collection="apps/local",
            links=_APP_LINKS, fields=False, acl_extra=_APP_ACL,
        )
        for app in _APPS
    ]
    return build_splunk_envelope(entries)


def _app_content(app: dict[str, object]) -> dict[str, object]:
    """An app's content block: its own values plus what every app carries.

    The entry's ``name`` is the app; splunkd does not repeat it inside
    ``content``, and doing so was reported as an extra key.
    """
    return {**_APP_COMMON, **{k: v for k, v in app.items() if k != "name"}}


@router.get("/services/apps/local/{name}")
def get_app(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Return a single installed app."""
    app = next((a for a in _APPS if a["name"] == name), None)
    if app is None:
        # splunkd's wording, measured: the object id, not the word "app".
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    entry = build_splunk_entry(
        name, _app_content(app), collection="apps/local",
        links=_APP_LINKS, fields=_APP_FIELDS, acl_extra=_APP_ACL,
    )
    return build_splunk_envelope([entry], total=1)


@router.get("/services/messages")
def list_messages(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List system messages. A healthy instance reports none."""
    return build_splunk_envelope([])


#: How splunkd classifies each command it knows. ``pipeline`` is the stage a
#: command runs in and ``streamType`` how it consumes events; a client reads
#: these to decide whether a query can be streamed or must be collected
#: first. Transcribed from Splunk 10.4.2's parser output.
_COMMAND_CLASSES: dict[str, tuple[str, str]] = {
    "search": ("streaming", "SP_STREAM"),
    "where": ("streaming", "SP_STREAM"),
    "eval": ("streaming", "SP_STREAM"),
    "rename": ("streaming", "SP_STREAM"),
    "fields": ("streaming", "SP_STREAM"),
    "table": ("streaming", "SP_STREAM"),
    "regex": ("streaming", "SP_STREAM"),
    "rex": ("streaming", "SP_STREAM"),
    "fillnull": ("streaming", "SP_STREAM"),
    "stats": ("report", "SP_STREAMREPORT"),
    "timechart": ("report", "SP_STREAMREPORT"),
    "top": ("report", "SP_STREAMREPORT"),
    "rare": ("report", "SP_STREAMREPORT"),
    "head": ("report", "SP_STATEFUL"),
    "tail": ("report", "SP_STATEFUL"),
    "sort": ("report", "SP_STATEFUL"),
    "dedup": ("report", "SP_STATEFUL"),
}

_PARSER_405 = {"messages": [{"type": "FATAL", "text": "The method is not allowed."}]}


def _parse_query(q: str) -> dict:
    """Parse a query the way ``POST /services/search/parser`` reports it.

    Not an Atom envelope: splunkd answers this endpoint with a flat object.
    mockdr wrapped it in ``entry[]`` through 2.0.3, served it at
    ``search/parse`` — a path splunkd does not have — and accepted GET, which
    splunkd refuses with 405. All three measured against Splunk 10.4.2.
    """
    if not q.strip():
        raise HTTPException(
            status_code=400,
            detail={"messages": [{"type": "FATAL", "text": "Invalid query."}]},
        )
    parsed = parse_spl(q)
    if parsed.errors:
        # splunkd's wording: the command in single quotes, and a full stop.
        unknown = next(
            (c.name for c in parsed.commands if c.name not in KNOWN_COMMANDS), None,
        )
        text = (
            f"Unknown search command '{unknown}'." if unknown else str(parsed.errors[0])
        )
        if not text.endswith("."):
            text += "."
        raise HTTPException(
            status_code=400, detail={"messages": [{"type": "FATAL", "text": text}]},
        )

    search_args = q.split("|")[0].strip()
    if search_args.lower().startswith("search "):
        search_args = search_args[7:].strip()

    commands: list[dict] = [{
        "command": "search",
        "rawargs": search_args,
        "pipeline": "streaming",
        "args": {"search": [search_args]},
        "isGenerating": True,
        "streamType": "SP_STREAM",
    }]
    report_stages: list[str] = []
    for command in parsed.commands:
        pipeline, stream_type = _COMMAND_CLASSES.get(command.name, ("streaming", "SP_STREAM"))
        entry: dict = {
            "command": command.name,
            "rawargs": command.arg,
            "pipeline": pipeline,
            "args": _command_args(command.name, command.arg),
            "isGenerating": False,
            "streamType": stream_type,
        }
        if pipeline == "report":
            # A report command also says what streaming work precedes it.
            # Measured for stats ("prestats count by host") and head
            # ("prehead limit=5 null=false keeplast=false"); the other report
            # commands follow the same pre<command> pattern by inference.
            entry["isStreamingOpRequired"] = False
            entry["preStreamingOp"] = _pre_streaming_op(command.name, command.arg)
            report_stages.append(f"{command.name} {command.arg}".strip())
        commands.append(entry)

    return {
        "remoteSearch": f"litsearch {search_args}",
        "normalizedSearch": f"litsearch {search_args}",
        "remoteTimeOrdered": True,
        "eventsSearch": f"search {search_args}",
        "eventsTimeOrdered": True,
        "eventsStreaming": True,
        "reportsSearch": " | ".join(report_stages),
        "isStreamingSearch": not report_stages,
        "canSummarize": False,
        "commands": commands,
    }


def _command_args(name: str, arg: str) -> object:
    """The parsed ``args`` splunkd reports for a command.

    Most commands carry their raw argument string. ``stats`` is structured:
    one ``stat-specifiers`` entry per aggregation with its function and
    output name, and ``groupby-fields`` for the ``by`` clause. That is what a
    client reads to learn which fields a query produces.
    """
    if name not in ("stats", "timechart", "top", "rare"):
        return arg
    head, _, by = arg.partition(" by ")
    specifiers = []
    for spec in filter(None, (s.strip() for s in head.split(","))):
        func_part, _, rename = spec.partition(" as ")
        function = func_part.split("(")[0].strip()
        specifiers.append({
            "function": function,
            "rename": rename.strip() or func_part.strip(),
        })
    return {
        "stat-specifiers": specifiers,
        "groupby-fields": [f.strip() for f in by.split(",") if f.strip()],
    }


def _pre_streaming_op(name: str, arg: str) -> str:
    """The streaming stage splunkd runs ahead of a report command."""
    if name == "head":
        limit = arg.strip() or "10"
        return f"prehead limit={limit} null=false keeplast=false"
    if name in ("stats", "timechart", "top", "rare"):
        return f"prestats {arg}".strip()
    return f"pre{name} {arg}".strip()


@router.post("/services/search/parser", operation_id="splunk_search_parser")
@router.post("/services/search/v2/parser", operation_id="splunk_search_v2_parser")
async def search_parser(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Validate a search without dispatching it; ``Service.parse()`` posts here."""
    form = await request.form()
    return _parse_query(str(form.get("q", "")))


@router.get("/services/search/parser", operation_id="splunk_search_parser_get")
@router.get("/services/search/v2/parser", operation_id="splunk_search_v2_parser_get")
def search_parser_get(
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Refused: the parser is POST-only, and splunkd says so with Allow: POST."""
    return JSONResponse(status_code=405, content=_PARSER_405, headers={"Allow": "POST"})
