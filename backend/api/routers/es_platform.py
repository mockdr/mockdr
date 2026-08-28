"""Kibana platform endpoints a client probes before it trusts the instance.

``/api/status``, ``/api/features`` and ``/api/spaces/space`` are how a client
establishes that it is talking to Kibana at all, and which space and features
it has. All three returned 404, so a client that checks before it acts
concluded the instance was not Kibana.

``/api/fleet/agents`` is the Fleet inventory the Elastic Agent tooling reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from api.es_auth import optional_es_auth, require_es_auth
from application.es_endpoints import queries as endpoint_queries
from config import APP_VERSION
from utils.es_response import build_kbn_error_response
from utils.kibana_query import EXCESS, INVALID_KEYS, refuses_unknown

router = APIRouter(tags=["Kibana Platform"])

_KIBANA_VERSION = "8.12.0"


@router.get("/api/status", dependencies=[refuses_unknown("v8format")])
async def kibana_status(request: Request) -> dict:
    """Report instance health, as ``/api/status`` does.

    Anyone may call it, but what they get depends on who they are. Kibana
    8.15 answers an anonymous caller with only the overall level, and a known
    user with the full document. This served the full document to everyone.
    """
    if await optional_es_auth(request) is None:
        return {"status": {"overall": {"level": "available"}}}
    return {
        "name": "mockdr-kibana",
        "uuid": "mockdr-0000-0000-0000-000000000001",
        "version": {
            "number": _KIBANA_VERSION,
            "build_hash": "a1b2c3d4e5f6",
            "build_number": 68900,
            "build_snapshot": False,
            # "traditional" is what a self-managed Kibana 8 reports; the
            # alternative is "serverless".
            "build_flavor": "traditional",
            "build_date": "2026-01-01T00:00:00.000Z",
        },
        "status": {
            "overall": {
                "level": "available",
                "summary": "All services and plugins are available",
            },
            "core": {
                "elasticsearch": {"level": "available", "summary": "Elasticsearch is available"},
                "savedObjects": {
                    "level": "available",
                    "summary": "SavedObjects service has completed migrations",
                },
            },
        },
        "metrics": {"collection_interval_in_millis": 5000},
        # mockdr's own version, so a caller can tell which mock it reached.
        "mockdr": {"version": APP_VERSION},
    }


#: All thirty-three of Kibana 8.15's features, verbatim from a running
#: instance. The feature catalogue is static configuration, and a client
#: reads deep into it — reserved privileges, alerting and cases grants,
#: management sections — so a hand-written subset kept missing whole
#: subtrees that only some features carry. Two report `privileges: null`.
_FEATURES: list[dict] = json.loads(
    (Path(__file__).resolve().parents[2] / "infrastructure" / "fixtures" / "kibana_features.json")
    .read_text(),
)


@router.get("/api/features", dependencies=[refuses_unknown("ignoreValidLicenses")])
def list_features(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List the Kibana features this instance exposes, as Kibana shapes them."""
    return _FEATURES


@router.get(
    "/api/spaces/space",
    dependencies=[refuses_unknown("purpose", "include_authorized_purposes")],
)
def list_spaces(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List Kibana spaces. This instance serves the default space only.

    Exactly the document Kibana 8.15 returns for its default space. It used
    to carry `color: null` and empty `initials`/`imageUrl`; Kibana omits a
    field it has no value for rather than sending it null or blank, and the
    default space does have a colour.
    """
    return [
        {
            "id": "default",
            "name": "Default",
            "description": "This is your default space!",
            "color": "#00bfb3",
            "disabledFeatures": [],
            "_reserved": True,
        }
    ]


@router.get("/api/spaces/space/{space_id}")
def get_space(
    space_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return one space by id, or 404 if there is no such space.

    Falling back to the default space told a client that whatever id it asked
    for exists — so a typo, or a space that had been deleted, read as success
    and the client went on to write into the wrong space.
    """
    spaces = list_spaces(_)
    space = next((s for s in spaces if s["id"] == space_id), None)
    if space is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(404, f"Saved object [space/{space_id}] not found"),
        )
    return space


@router.get(
    "/api/fleet/agents",
    dependencies=[refuses_unknown(
        "page", "perPage", "kuery", "showInactive", "showUpgradeable", "sortField",
        "sortOrder", "getStatusSummary", "withMetrics",
    )],
)
def list_fleet_agents(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=1000, alias="perPage"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """List Fleet agents, derived from the same endpoints the metadata API serves."""
    listing = endpoint_queries.list_endpoints(page=page, per_page=per_page)
    entries = listing.get("data", [])

    agents = [_fleet_agent(entry) for entry in entries]
    return {
        "items": agents,
        # Fleet still sends `list`, the pre-8.x name, beside `items` (measured).
        "list": agents,
        "total": listing.get("total", len(entries)),
        "page": page,
        "perPage": per_page,
    }


def _fleet_agent(entry: dict) -> dict:
    """Render one endpoint as the Fleet agent record that backs it."""
    metadata = entry.get("metadata", {})
    agent = metadata.get("agent", {})
    host = metadata.get("host", {})
    return {
        "id": agent.get("id", ""),
        "type": "PERMANENT",
        "active": True,
        "enrolled_at": metadata.get("@timestamp", ""),
        "last_checkin": metadata.get("@timestamp", ""),
        "policy_id": (
            metadata.get("Endpoint", {}).get("policy", {}).get("applied", {}).get("id", "")
        ),
        "policy_revision": 1,
        "status": entry.get("host_status", "healthy"),
        "local_metadata": {
            "host": {"hostname": host.get("hostname", ""), "name": host.get("name", "")},
            "os": host.get("os", {}),
            "elastic": {
                "agent": {
                    "id": agent.get("id", ""),
                    "version": agent.get("version", ""),
                }
            },
        },
    }


# ── The rest of the platform surface ─────────────────────────────────────────
#
# An endpoint sweep against a running Kibana found these answering 404 here.
# Each is small, and each is something a client calls *around* the work: it
# lists the saved objects and data views to find out what it can search,
# reads Fleet's policies and readiness, and — where it only has Kibana —
# talks to Elasticsearch through the console proxy.


@router.get("/api/saved_objects/_find")
def find_saved_objects(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=0, le=10000),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find saved objects of a type.

    The `type` is required, and Kibana says so in the words its config
    schema uses — a client that forgets it gets a 400 rather than every
    object there is.
    """
    if not request.query_params.getlist("type"):
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400,
            "[request query.type]: expected at least one defined value but got "
            "[undefined]",
        ))
    return {"page": page, "per_page": per_page, "total": 0, "saved_objects": []}


@router.get("/api/data_views")
def list_data_views(_: dict = Depends(require_es_auth)) -> dict:
    """The data views this space defines, of which mockdr defines none."""
    return {"data_view": []}


@router.get(
    "/api/fleet/agent_policies",
    dependencies=[refuses_unknown(
        "page", "perPage", "kuery", "sortField", "sortOrder", "full", "noAgentCount",
    )],
)
def list_agent_policies(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=1000, alias="perPage"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """The Fleet policies agents are enrolled into."""
    return {"items": [], "page": page, "perPage": per_page, "total": 0}


@router.get("/api/fleet/agents/setup")
def fleet_setup(_: dict = Depends(require_es_auth)) -> dict:
    """Whether Fleet is ready to enrol agents.

    mockdr's Fleet holds agents, so it says it is ready — where a fresh
    Kibana with no Fleet server reports `fleet_server` missing.
    """
    return {
        "isReady": True,
        "is_secrets_storage_enabled": False,
        "missing_requirements": [],
        "missing_optional_features": [],
        "package_verification_key_id": "d27d666cd88e42b4",
    }


@router.get("/api/timelines")
def list_timelines(_: dict = Depends(require_es_auth)) -> dict:
    """The Security Solution timelines this space holds."""
    return {
        "timeline": [],
        "totalCount": 0,
        "defaultTimelineCount": 0,
        "templateTimelineCount": 0,
        "favoriteCount": 0,
        "elasticTemplateTimelineCount": 0,
        "customTemplateTimelineCount": 0,
    }


@router.get(
    "/api/timeline",
    dependencies=[refuses_unknown("id", "template_timeline_id", dialect=EXCESS)],
)
def get_timeline(
    _id: str | None = Query(default=None, alias="id"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """One timeline. A timeline that is not there is an empty object there."""
    return {}


@router.get(
    "/api/note",
    dependencies=[refuses_unknown(
        "page", "perPage", "search", "sortField", "sortOrder", "filter", "documentIds",
    )],
)
def list_notes(_: dict = Depends(require_es_auth)) -> dict:
    """The notes attached to timelines and events."""
    return {"notes": [], "totalCount": 0}


@router.get(
    "/api/cases/configure",
    dependencies=[refuses_unknown("owner", dialect=INVALID_KEYS)],
)
def case_configuration(_: dict = Depends(require_es_auth)) -> list[dict]:
    """The case connectors this space configures, of which mockdr has none."""
    return []


@router.get("/api/osquery/packs")
def osquery_packs(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=0, le=1000),
    _: dict = Depends(require_es_auth),
) -> dict:
    """The Osquery packs this space defines, of which mockdr defines none."""
    return {"page": page, "per_page": per_page, "total": 0, "data": []}


@router.post("/api/console/proxy")
async def console_proxy(
    request: Request,
    path: str | None = Query(default=None),
    method: str = Query(default="GET"),
    _: dict = Depends(require_es_auth),
) -> Response:
    """Talk to Elasticsearch through Kibana, the way the console does.

    A client that only reaches Kibana uses this as its gateway, and mockdr
    answered 404 — so the gateway was closed. The request is forwarded to
    this instance's own Elasticsearch API and the answer relayed as it came,
    pretty-printed the way the console shows it. Note what the *proxy*
    answers: 200, whatever Elasticsearch said, with the error in the body
    (measured).
    """
    if not path:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400,
            "[request query.path]: expected value of type [string] but got "
            "[undefined]",
        ))
    body = await request.body()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=request.app), base_url="http://mockdr",
    ) as client:
        answer = await client.request(
            method.upper(),
            f"/elastic/{path.lstrip('/')}",
            content=body or None,
            headers={
                "Authorization": request.headers.get("authorization", ""),
                "Content-Type": "application/json",
            },
        )
    content_type = answer.headers.get("content-type", "application/json")
    if content_type.startswith("application/json"):
        return Response(
            content=_console_json(answer.text),
            media_type="application/json; charset=utf-8",
        )
    return Response(content=answer.text, media_type=content_type)


def _console_json(text: str) -> str:
    """Elasticsearch's own pretty printing, which the console asks for.

    Two-space indentation and a space either side of the colon — a client
    that diffs the body against a recorded one sees the difference.
    """
    try:
        document = json.loads(text)
    except ValueError:
        return text
    return json.dumps(document, indent=2).replace('": ', '" : ') + "\n"
