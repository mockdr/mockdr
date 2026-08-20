"""Kibana platform endpoints a client probes before it trusts the instance.

``/api/status``, ``/api/features`` and ``/api/spaces/space`` are how a client
establishes that it is talking to Kibana at all, and which space and features
it has. All three returned 404, so a client that checks before it acts
concluded the instance was not Kibana.

``/api/fleet/agents`` is the Fleet inventory the Elastic Agent tooling reads.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.es_auth import require_es_auth
from application.es_endpoints import queries as endpoint_queries
from config import APP_VERSION

router = APIRouter(tags=["Kibana Platform"])

_KIBANA_VERSION = "8.12.0"


@router.get("/api/status")
def kibana_status() -> dict:
    """Report instance health, as ``/api/status`` does. No auth required."""
    return {
        "name": "mockdr-kibana",
        "uuid": "mockdr-0000-0000-0000-000000000001",
        "version": {
            "number": _KIBANA_VERSION,
            "build_hash": "a1b2c3d4e5f6",
            "build_number": 68900,
            "build_snapshot": False,
            "build_flavor": "default",
            "build_date": "2026-01-01T00:00:00.000Z",
        },
        "status": {
            "overall": {
                "level": "available",
                "summary": "All services are available",
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


@router.get("/api/features")
def list_features(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List the Kibana features this instance exposes."""
    return [
        {
            "id": "siem",
            "name": "Security",
            "category": {"id": "securitySolution", "label": "Security"},
            "app": ["securitySolution", "kibana"],
            "privileges": {
                "all": {
                    "app": ["securitySolution"],
                    "savedObject": {"all": ["alert"], "read": []},
                },
                "read": {
                    "app": ["securitySolution"],
                    "savedObject": {"all": [], "read": ["alert"]},
                },
            },
        },
        {
            "id": "securitySolutionCases",
            "name": "Cases",
            "category": {"id": "securitySolution", "label": "Security"},
            "app": ["securitySolution", "kibana"],
            "privileges": {
                "all": {
                    "app": ["securitySolution"],
                    "savedObject": {"all": ["cases"], "read": []},
                },
                "read": {
                    "app": ["securitySolution"],
                    "savedObject": {"all": [], "read": ["cases"]},
                },
            },
        },
        {
            "id": "fleet",
            "name": "Fleet",
            "category": {"id": "management", "label": "Management"},
            "app": ["fleet", "kibana"],
            "privileges": {
                "all": {
                    "app": ["fleet"],
                    "savedObject": {"all": ["ingest-agent-policies"], "read": []},
                },
                "read": {
                    "app": ["fleet"],
                    "savedObject": {"all": [], "read": ["ingest-agent-policies"]},
                },
            },
        },
    ]


@router.get("/api/spaces/space")
def list_spaces(
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List Kibana spaces. This instance serves the default space only."""
    return [{
        "id": "default",
        "name": "Default",
        "description": "This is the default space",
        "color": None,
        "initials": "D",
        "imageUrl": "",
        "disabledFeatures": [],
        "_reserved": True,
    }]


@router.get("/api/spaces/space/{space_id}")
def get_space(
    space_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return one space by id."""
    spaces = list_spaces(_)
    return next((s for s in spaces if s["id"] == space_id), spaces[0])


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
