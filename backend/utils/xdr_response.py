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


def require_str_list(request_data: dict, key: str) -> list[str]:
    """Return ``request_data[key]`` as a list of strings, or refuse the request.

    ``hash_list`` and its kind are flat lists of strings. Handed a list of
    objects — the shape a reader might guess from the ``comment`` that sits
    beside it — the handler used to reach for ``.get`` on a string and answer
    a plain-text 500. A malformed value is the caller's mistake, and XDR
    reports it as a 400.
    """
    from fastapi import HTTPException  # local: utils must not import the API layer at module load

    value = request_data.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, (str, int)) for v in value):
        raise HTTPException(
            status_code=400,
            detail=build_xdr_error(
                400, "Bad Request", f"{key} must be an array of strings",
            ),
        )
    return [str(v) for v in value]


def serialise_endpoint(record: dict) -> dict:
    """One endpoint as Cortex serves it, wherever it is served.

    The tags assigned through ``/tags/agents/assign/`` are held as a list and
    served in ``endpointTags``, which the reference example types as a
    string — so they are joined, and the internal spelling does not leak.
    Both the API and the Splunk bridge render endpoints through here, because
    the bridge's whole point is that the event and the API object are the
    same record.
    """
    rendered = dict(record)
    rendered.pop("isolation_requested_at", None)  # mockdr's own bookkeeping
    tags = rendered.pop("endpoint_tags", []) or []
    rendered["endpointTags"] = ",".join(tags) if isinstance(tags, list) else str(tags)
    return rendered


#: The most records Cortex answers per page on the routes that page with
#: `search_from`/`search_to` and document a ceiling: incidents ("0 <
#: search_size <= 100", Palo Alto LIVEcommunity on get_incidents) and
#: endpoints (XSOAR CoreIRApiModule `get_endpoints_command`: "the max limit
#: supported by the API (100)").
XDR_MAX_PAGE = 100


def page_bounds(request_data: dict, cap: int | None = None) -> tuple[int, int]:
    """The ``search_from``/``search_to`` slice a request asks for.

    A string, float or object here used to reach a list slice and answer a
    plain 500 (``"0"`` included); it is the request's mistake, answered 400
    in the XDR envelope. ``search_to`` defaults to a page past
    ``search_from``; with ``cap`` the page is never longer than that.
    """
    from fastapi import HTTPException  # local: utils must not import the API layer at module load

    def bound(key: str, default: int) -> int:
        value = request_data.get(key, default)
        if value is None:
            return default
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HTTPException(
                status_code=400,
                detail=build_xdr_error(
                    400, "Bad Request", f"{key} must be a non-negative integer",
                ),
            )
        return value

    search_from = bound("search_from", 0)
    search_to = bound("search_to", search_from + (cap or XDR_MAX_PAGE))
    if cap is not None:
        search_to = min(search_to, search_from + cap)
    return search_from, search_to
