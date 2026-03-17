"""Azure Resource Manager (ARM) response envelope builders for Sentinel.

Every Sentinel resource follows the ARM pattern:
- Single: ``{"id": "...", "name": "...", "type": "...", "properties": {...}}``
- List:   ``{"value": [...], "nextLink": "..."}``
- Error:  ``{"error": {"code": "...", "message": "..."}}``
"""
from __future__ import annotations

_SUB = "00000000-0000-0000-0000-000000000000"
_RG = "mockdr-rg"
_WS = "mockdr-workspace"
_BASE = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{_WS}"
    f"/providers/Microsoft.SecurityInsights"
)


def build_arm_resource(
    resource_type: str,
    name: str,
    properties: dict,
    *,
    etag: str = "",
) -> dict:
    """Build a single ARM resource envelope.

    Args:
        resource_type: e.g. ``"incidents"``, ``"alertRules"``.
        name:          Resource name / ID.
        properties:    The resource-specific property bag.
        etag:          Optional ETag value.

    Returns:
        ARM resource dict.
    """
    result: dict = {
        "id": f"{_BASE}/{resource_type}/{name}",
        "name": name,
        "type": f"Microsoft.SecurityInsights/{resource_type}",
        "properties": properties,
    }
    if etag:
        result["etag"] = f'"{etag}"'
    return result


def build_arm_list(
    items: list[dict],
    *,
    next_link: str = "",
) -> dict:
    """Build an ARM list response envelope.

    Args:
        items:     List of ARM resource dicts.
        next_link: Optional pagination URL.

    Returns:
        ARM list response dict.
    """
    result: dict = {"value": items}
    if next_link:
        result["nextLink"] = next_link
    return result


def build_arm_error(code: str, message: str) -> dict:
    """Build an ARM error response body.

    Args:
        code:    Error code string.
        message: Human-readable error message.

    Returns:
        ARM error envelope dict.
    """
    return {"error": {"code": code, "message": message}}


def build_log_analytics_response(
    columns: list[dict[str, str]],
    rows: list[list],
) -> dict:
    """Build a Log Analytics query response.

    Args:
        columns: List of ``{"name": "...", "type": "..."}`` dicts.
        rows:    List of row arrays.

    Returns:
        Log Analytics response dict.
    """
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": columns,
            "rows": rows,
        }],
    }
