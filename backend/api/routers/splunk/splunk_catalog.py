"""Splunk service-catalogue endpoints.

``/services``, ``/services/apps/local`` and ``/services/messages`` are the
first calls a client makes to discover what a splunkd instance offers, and
``/services/search/parse`` is what ``splunklib``'s ``Service.parse()`` uses to
validate a query without dispatching it. All four returned 404, so a client
probing the instance concluded it was talking to something that was not Splunk.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

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
        build_splunk_entry(str(app["name"]), dict(app), collection="apps/local")
        for app in _APPS
    ]
    return build_splunk_envelope(entries)


@router.get("/services/apps/local/{name}")
def get_app(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Return a single installed app."""
    app = next((a for a in _APPS if a["name"] == name), None)
    if app is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"App '{name}' does not exist"},
        ]})
    entry = build_splunk_entry(name, dict(app), collection="apps/local")
    return build_splunk_envelope([entry], total=1)


@router.get("/services/messages")
def list_messages(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List system messages. A healthy instance reports none."""
    return build_splunk_envelope([])


@router.post("/services/search/parse")
@router.get("/services/search/parse")
def parse_search(
    q: str = Query(default="", alias="q"),
    output_mode: str = "json",
    parse_only: str = Query(default="", alias="parse_only"),
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Validate a search without dispatching it.

    ``splunklib``'s ``Service.parse()`` posts here to check a query before
    running it. A query naming a command the engine cannot run is reported as
    an error, which is the entire point of the endpoint.
    """
    if not q.strip():
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Search query is required"},
        ]})

    parsed = parse_spl(q)
    if parsed.errors:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": text} for text in parsed.errors
        ]})

    commands = ["search", *[c.name for c in parsed.commands]]
    entry = build_splunk_entry(
        "parse",
        {
            "commands": commands,
            "index": parsed.index,
            "sourcetype": parsed.sourcetype,
            "remoteSearch": q,
            "eventsSearch": q.split("|")[0].strip(),
            "canSummarize": False,
            "isSaved": False,
            "supportedCommands": sorted(KNOWN_COMMANDS),
        },
        collection="search/parse",
    )
    return build_splunk_envelope([entry], total=1)
