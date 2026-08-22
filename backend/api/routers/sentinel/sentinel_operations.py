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
    # ARM's operation list: every entry carries origin and isDataAction, the
    # display block a description, and the envelope a nextLink — all absent
    # here until the 2024-03-01 spec was compared against this route.
    return {
        "value": [
            {
                **op,
                "origin": op.get("origin", "user,system"),
                "isDataAction": op.get("isDataAction", False),
                "display": {
                    **op.get("display", {}),
                    "description": op.get("display", {}).get(
                        "description", op.get("display", {}).get("operation", ""),
                    ),
                },
            }
            for op in _OPERATIONS
        ],
        # No nextLink: ARM omits it when there is no next page, rather than
        # sending null — the spec declares the property, practice leaves it out.
    }
