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

router = APIRouter(tags=["Splunk Catalog"])

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
    # Measured on Splunk 10.4.2, one probe per command. Three of the report
    # stage's guesses were wrong: sort and tail run in the *events* pipeline
    # as SP_EVENTS, and dedup is its own *stateful* stage.
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
    "dedup": ("stateful", "SP_STATEFUL"),
    "sort": ("events", "SP_EVENTS"),
    "tail": ("events", "SP_EVENTS"),
}

#: Generating commands splunkd has and mockdr's engine cannot run. The
#: parser must still classify them — refusing them with splunkd's own
#: "Unknown search command" wording made a mockdr limitation look like the
#: caller's typo. Both measured on 10.4.2; others are still refused.
_GENERATING: dict[str, tuple[str, str, bool, str]] = {
    "makeresults": ("report", "SP_STREAMREPORT", True, "premakeresults"),
    "inputlookup": ("report", "SP_REPORT", True, ""),
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
    stages = [st.strip() for st in _split_top_level(q)]
    leading_pipe = q.lstrip().startswith("|")
    names = [st.split(None, 1)[0].lower() if st else "" for st in stages]
    if leading_pipe:
        stages, names = stages[1:], names[1:]
    known = _COMMAND_CLASSES.keys() | _GENERATING.keys()
    later = names if leading_pipe else names[1:]
    unknown = next((n for n in later if n and n not in known), None)
    first = names[0] if names else ""
    first_is_unknown = first not in ("search", "") and first not in known
    if not leading_pipe and first_is_unknown:
        unknown = names[0]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail={"messages": [
                {"type": "FATAL", "text": f"Unknown search command '{unknown}'."},
            ]},
        )

    commands: list[dict] = []
    report_stages: list[str] = []
    if leading_pipe:
        # A generating command comes first and there is no `search` stage at
        # all; eventsSearch is empty (measured for makeresults, inputlookup).
        search_args = ""
        first = stages[0]
        name, _, arg = first.partition(" ")
        name = name.lower()
        pipeline, stream_type, required, pre = _GENERATING[name]
        commands.append({
            "command": name, "rawargs": f" {arg} ", "pipeline": pipeline,
            "args": f" {arg} ", "isGenerating": True, "streamType": stream_type,
            "isStreamingOpRequired": required,
            "preStreamingOp": f"{pre} {arg} " if pre else "",
        })
        rest = stages[1:]
    else:
        search_args = stages[0] if stages else ""
        if search_args.lower().startswith("search "):
            search_args = search_args[7:].strip()
        elif search_args.lower() == "search":
            search_args = ""
        commands.append({
            "command": "search", "rawargs": search_args, "pipeline": "streaming",
            "args": {"search": [search_args]}, "isGenerating": True, "streamType": "SP_STREAM",
        })
        rest = stages[1:]

    for stage in rest:
        cname, _, carg = stage.partition(" ")
        cname = cname.lower()
        pipeline, stream_type = _COMMAND_CLASSES.get(cname, ("streaming", "SP_STREAM"))
        entry: dict = {
            "command": cname, "rawargs": carg, "pipeline": pipeline,
            "args": _command_args(cname, carg), "isGenerating": False, "streamType": stream_type,
        }
        if pipeline != "streaming":
            # Every non-streaming stage says what streaming work precedes it.
            required, op = _pre_streaming_op(cname, carg)
            entry["isStreamingOpRequired"] = required
            entry["preStreamingOp"] = op
            report_stages.append(f"{cname} {carg}".strip())
        commands.append(entry)

    return {
        "remoteSearch": f"litsearch {search_args}",
        "normalizedSearch": f"litsearch {search_args}",
        "remoteTimeOrdered": True,
        # A generating command has no events search at all (measured: "").
        "eventsSearch": f"search {search_args}" if not leading_pipe else "",
        "eventsTimeOrdered": True,
        "eventsStreaming": True,
        "reportsSearch": " | ".join(report_stages),
        "isStreamingSearch": not report_stages,
        "canSummarize": False,
        "commands": commands,
    }


def _command_args(name: str, arg: str) -> object:
    """The parsed ``args`` splunkd reports for a command.

    Most commands carry their raw argument string. The reporting commands
    are structured, each in its own shape, all measured on 10.4.2: stats and
    timechart carry ``stat-specifiers``; top and rare carry their limit,
    display options and ``fields``. That is what a client reads to learn
    which fields a query produces.
    """
    if name in ("stats", "timechart"):
        head, _, by = _partition_ci(arg, " by ")
        specs = []
        for spec in filter(None, (s.strip() for s in head.split(","))):
            if name == "timechart":
                # span=1h and friends are options, not aggregations; they
                # share the clause with the aggregation they modify.
                spec = " ".join(t for t in spec.split() if "=" not in t.split("(")[0])
                if not spec:
                    continue
            func_part, _, rename = _partition_ci(spec, " as ")
            # dc(host) carries its field; a bare count does not (10.4.2).
            field = func_part.partition("(")[2].rstrip(")").strip()
            entry = {"function": func_part.split("(")[0].strip()}
            if field:
                entry["field"] = field
            entry["rename"] = rename.strip() or func_part.strip()
            specs.append(entry)
        if name == "stats":
            return {
                "stat-specifiers": specs,
                "groupby-fields": [f.strip() for f in by.split(",") if f.strip()],
            }
        options = [t for t in arg.split() if "=" in t and "(" not in t]
        return {
            "stat-specifiers": specs,
            "xfield": "_time",
            "xfieldopts": options,
            "seriesfield": by.strip().split(",")[0].strip() if by.strip() else "",
            "usenull": True,
            "nullstr": "NULL",
            "useother": True,
            "otherstr": "OTHER",
            "seriesfilter": "sum IN top10",
        }
    if name in ("top", "rare"):
        tokens = arg.split()
        limits = [int(t[6:]) for t in tokens if t.startswith("limit=") and t[6:].isdigit()]
        limit = limits[0] if limits else 10
        fields = [t for t in tokens if "=" not in t]
        return {
            "limit": limit, "showperc": True, "showcount": True,
            "percentfield": "percent", "countfield": "count", "fields": fields,
        }
    # sort, dedup, head and tail report the raw string with its leading space.
    return f" {arg}" if arg and not arg.startswith(" ") else arg


def _partition_ci(text: str, sep: str) -> tuple[str, str, str]:
    """``str.partition`` that ignores case, because SPL keywords do."""
    at = text.lower().find(sep)
    if at < 0:
        return text, "", ""
    return text[:at], sep, text[at + len(sep):]


def _split_top_level(query: str) -> list[str]:
    """Split a query on pipes that are not inside double quotes."""
    stages: list[str] = []
    buf: list[str] = []
    quoted = False
    for ch in query:
        if ch == '"':
            quoted = not quoted
        if ch == "|" and not quoted:
            stages.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    stages.append("".join(buf))
    return stages


#: Measured per command on 10.4.2. An empty string means splunkd reports
#: none (tail); sort's is the only one that needs the streaming op.
def _pre_streaming_op(name: str, arg: str) -> tuple[bool, str]:
    """``(isStreamingOpRequired, preStreamingOp)`` as splunkd reports them."""
    a = arg.strip()
    if name == "head":
        return False, f"prehead limit={a or '10'} null=false keeplast=false"
    if name in ("stats", "timechart", "top", "rare"):
        return False, f"prestats {a}".strip()
    if name == "sort":
        field = a.lstrip("-+") or "_time"
        return True, f"presort 10000 -auto({field})"
    if name == "dedup":
        return False, f'prededup 1 keepempty=false consecutive=false keepevents=false "{a}"'
    return False, ""


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
