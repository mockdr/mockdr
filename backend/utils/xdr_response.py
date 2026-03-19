"""Palo Alto Cortex XDR API response envelope builders.

Cortex XDR wraps all responses in a ``{"reply": ...}`` envelope:
- Success list endpoints return ``{"reply": {"total_count": N, "result_count": N, "data": [...]}}``
- Single/action endpoints return ``{"reply": <data>}``
- Errors return ``{"reply": {"err_code": N, "err_msg": "...", "err_extra": "..."}}``
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_xdr_reply(data: object) -> dict:
    """Build a generic XDR reply envelope.

    Args:
        data: Any JSON-serialisable payload.

    Returns:
        ``{"reply": data}``
    """
    return {"reply": data}


def build_xdr_list_reply(
    items: list[dict],
    total_count: int,
    result_count: int | None = None,
    key: str = "data",
) -> dict:
    """Build an XDR paginated list response.

    Args:
        items:        Page of resource objects.
        total_count:  Total number of matching records.
        result_count: Number of records in this page (defaults to ``len(items)``).
        key:          Key name for the items list (default ``"data"``).

    Returns:
        XDR list response dict.
    """
    return {
        "reply": {
            "total_count": total_count,
            "result_count": result_count if result_count is not None else len(items),
            key: items,
        },
    }


def build_xdr_error(err_code: int, err_msg: str, err_extra: str = "") -> dict:
    """Build a Cortex XDR error response.

    Args:
        err_code:  Numeric error code.
        err_msg:   Human-readable error message.
        err_extra: Optional additional context.

    Returns:
        XDR error envelope dict.
    """
    return {
        "reply": {
            "err_code": err_code,
            "err_msg": err_msg,
            "err_extra": err_extra,
        },
    }
