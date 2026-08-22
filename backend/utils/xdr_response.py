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


#: The wording Cortex XDR documents for each status it defines. ``err_code``
#: mirrors the HTTP status rather than being a separate code space, and there
#: is no documented 400 — Palo Alto lists only these.
XDR_ERR_UNAUTHORIZED = (
    "Unauthorized access. An issue occurred during authentication. This can "
    "indicate an incorrect key, id, or other invalid authentication parameters."
)
XDR_ERR_LICENSE = (
    "Unauthorized access. User does not have the required license type to run this API."
)
XDR_ERR_FORBIDDEN = (
    "Unauthorized access. The provided API key does not have the required RBAC "
    "permissions to run this API."
)
XDR_ERR_NOT_FOUND = "XDR Not found: The provided URL may not be of an active XDR server."
XDR_ERR_TOO_LARGE = "Request entity too large. Please reach out to the XDR support team."
XDR_ERR_INTERNAL = "XDR internal server error."

XDR_DOCUMENTED_ERRORS: dict[int, str] = {
    401: XDR_ERR_UNAUTHORIZED,
    402: XDR_ERR_LICENSE,
    403: XDR_ERR_FORBIDDEN,
    404: XDR_ERR_NOT_FOUND,
    413: XDR_ERR_TOO_LARGE,
    500: XDR_ERR_INTERNAL,
}


def build_xdr_error(err_code: int, err_msg: str, err_extra: str | None = None) -> dict:
    """Build a Cortex XDR error response.

    Args:
        err_code:  Numeric error code, mirroring the HTTP status.
        err_msg:   Human-readable error message.
        err_extra: Optional additional context; ``null`` when absent, which is
                   what the API sends when it has nothing to add — an empty
                   string is a value a client may print.

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


def require_request_data(body: object) -> dict:
    """Return ``body["request_data"]``, or refuse the request the way XDR does.

    Every XDR call carries its parameters under ``request_data``. A body with
    none — ``{}``, ``null``, an array — used to fall through to the handler
    with an empty dict, which then looked up an endpoint named ``""`` and
    reported an *internal* error. A malformed request is the caller's
    mistake, and XDR says so with a 400.
    """
    from fastapi import HTTPException  # local: utils must not import the API layer at module load

    request_data = body.get("request_data") if isinstance(body, dict) else None
    if not isinstance(request_data, dict):
        raise HTTPException(
            status_code=400,
            detail=build_xdr_error(
                400, "Bad Request", "request_data is required and must be an object",
            ),
        )
    return request_data
