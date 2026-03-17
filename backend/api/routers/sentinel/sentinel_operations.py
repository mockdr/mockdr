"""Sentinel Operations metadata router."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["Sentinel Operations"])

_OPERATIONS: list[dict] = [
    {
        "name": "Microsoft.SecurityInsights/incidents/read",
        "display": {
            "provider": "Microsoft Security Insights",
            "resource": "Incidents",
            "operation": "Read",
        },
    },
    {
        "name": "Microsoft.SecurityInsights/incidents/write",
        "display": {
            "provider": "Microsoft Security Insights",
            "resource": "Incidents",
            "operation": "Write",
        },
    },
    {
        "name": "Microsoft.SecurityInsights/incidents/delete",
        "display": {
            "provider": "Microsoft Security Insights",
            "resource": "Incidents",
            "operation": "Delete",
        },
    },
    {
        "name": "Microsoft.SecurityInsights/alertRules/read",
        "display": {
            "provider": "Microsoft Security Insights",
            "resource": "Alert Rules",
            "operation": "Read",
        },
    },
    {
        "name": "Microsoft.SecurityInsights/watchlists/read",
        "display": {
            "provider": "Microsoft Security Insights",
            "resource": "Watchlists",
            "operation": "Read",
        },
    },
]


@router.get("/providers/Microsoft.SecurityInsights/operations")
def list_operations() -> dict:
    """Return available Sentinel operations metadata."""
    return {"value": _OPERATIONS}
