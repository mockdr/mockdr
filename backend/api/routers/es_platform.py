"""Kibana platform endpoints a client probes before it trusts the instance.

``/api/status``, ``/api/features`` and ``/api/spaces/space`` are how a client
establishes that it is talking to Kibana at all, and which space and features
it has. All three returned 404, so a client that checks before it acts
concluded the instance was not Kibana.

``/api/fleet/agents`` is the Fleet inventory the Elastic Agent tooling reads.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.es_auth import optional_es_auth, require_es_auth
from application.es_endpoints import queries as endpoint_queries
from config import APP_VERSION
from utils.es_response import build_kbn_error_response

router = APIRouter(tags=["Kibana Platform"])

_KIBANA_VERSION = "8.12.0"


@router.get("/api/status")
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


def _feature(
    fid: str, name: str, order: int, category: tuple[str, str, int, str], app: list[str],
    catalogue: list[str], saved_all: list[str], api: list[str], ui: list[str],
) -> dict:
    """One feature in the shape Kibana 8.15 reports (measured via /api/features)."""
    cat_id, label, cat_order, icon = category
    def privilege(all_: bool) -> dict:
        return {
            "app": app, "catalogue": catalogue,
            "api": (
                api if all_ else [a for a in api if "read" in a] or api[:1]
            ),
            "savedObject": {"all": saved_all if all_ else [], "read": [] if all_ else saved_all},
            "ui": ui if all_ else [u for u in ui if u in ("show", "read")] or ui[:1],
            "alerting": {}, "management": {},
        }
    return {
        "id": fid, "name": name, "order": order,
        "category": {"id": cat_id, "label": label, "order": cat_order, "euiIconType": icon},
        "app": app, "catalogue": catalogue, "management": {}, "alerting": [],
        "privileges": {"all": privilege(True), "read": privilege(False)},
        "subFeatures": [],
    }


_SECURITY = ("securitySolution", "Security", 4000, "logoSecurity")
_MANAGEMENT = ("management", "Management", 5000, "managementApp")


@router.get("/api/features")
def list_features(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List the Kibana features this instance exposes.

    Three of Kibana's thirty-three, each in the full shape — order,
    catalogue, management, alerting, subFeatures, and privileges carrying
    api/ui/savedObject — so a client that reads any of those keys finds
    them. Previously each feature carried a quarter of its keys.
    """
    return [
        _feature("siem", "Security", 1100, _SECURITY, ["securitySolution", "kibana"],
                 ["securitySolution"], ["alert", "exception-list", "exception-list-agnostic"],
                 ["securitySolution", "lists-all", "lists-read", "rac"],
                 ["show", "crud"]),
        _feature("securitySolutionCases", "Cases", 1100, _SECURITY, ["securitySolution", "kibana"],
                 ["securitySolution"], ["cases", "cases-comments", "cases-user-actions"],
                 ["casesSuggestUserProfiles", "bulkGetUserProfiles"],
                 ["create_cases", "read_cases", "update_cases", "delete_cases"]),
        _feature("fleet", "Fleet", 9020, _MANAGEMENT, ["fleet", "kibana"], ["fleet"],
                 ["ingest-agent-policies", "fleet-agents", "ingest-package-policies"],
                 ["fleet-all", "fleet-read"], ["read", "all"]),
        # Two of Kibana's features report no privileges at all (measured:
        # enterpriseSearch and monitoring). A client must cope with null.
        {
            "id": "monitoring", "name": "Stack Monitoring", "order": 3500,
            "category": {"id": "management", "label": "Management", "order": 5000,
                         "euiIconType": "managementApp"},
            "app": ["monitoring", "kibana"], "catalogue": ["monitoring"],
            "management": {}, "alerting": [], "privileges": None, "subFeatures": [],
        },
    ]


@router.get("/api/spaces/space")
def list_spaces(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List Kibana spaces. This instance serves the default space only.

    Exactly the document Kibana 8.15 returns for its default space. It used
    to carry `color: null` and empty `initials`/`imageUrl`; Kibana omits a
    field it has no value for rather than sending it null or blank, and the
    default space does have a colour.
    """
    return [{
        "id": "default",
        "name": "Default",
        "description": "This is your default space!",
        "color": "#00bfb3",
        "disabledFeatures": [],
        "_reserved": True,
    }]


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


@router.get("/api/fleet/agents")
def list_fleet_agents(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=1000, alias="perPage"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """List Fleet agents, derived from the same endpoints the metadata API serves."""
    listing = endpoint_queries.list_endpoints(page=page, per_page=per_page)
    entries = listing.get("data", [])

    return {
        "items": [_fleet_agent(entry) for entry in entries],
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
            "elastic": {"agent": {
                "id": agent.get("id", ""), "version": agent.get("version", ""),
            }},
        },
    }
