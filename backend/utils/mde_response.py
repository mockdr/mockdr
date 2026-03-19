"""Microsoft Defender for Endpoint API response envelope builders.

MDE uses OData v4 conventions:
- List endpoints return ``{"@odata.context": "...", "value": [...]}``
- Single entities are returned as bare dicts (no envelope)
- Errors use ``{"error": {"code": "...", "message": "..."}}``
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_mde_list_response(
    value: list[dict],
    context: str = "https://api.securitycenter.microsoft.com/api/$metadata",
    next_link: str | None = None,
) -> dict:
    """Build an OData v4 list response envelope.

    Args:
        value:     Page of resource objects.
        context:   OData context URL (cosmetic).
        next_link: Optional ``@odata.nextLink`` for pagination.

    Returns:
        OData list response dict.
    """
    resp: dict = {"@odata.context": context, "value": value}
    if next_link:
        resp["@odata.nextLink"] = next_link
    return resp


def build_mde_entity_response(entity: dict) -> dict:
    """Return a single MDE entity (no envelope — bare dict).

    Args:
        entity: The entity dict to return.

    Returns:
        The entity dict unchanged.
    """
    return entity


def build_mde_error_response(code: str, message: str) -> dict:
    """Build an MDE-style error response.

    Args:
        code:    Error code string (e.g. ``"NotFound"``).
        message: Human-readable error description.

    Returns:
        MDE error envelope dict.
    """
    return {
        "error": {
            "code": code,
            "message": message,
        },
    }
