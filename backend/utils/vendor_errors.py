"""Vendor-shaped error envelopes for framework-level failures.

Errors raised inside a router already carry the right envelope for the vendor
that router mocks. Failures raised *before* a handler runs — request validation
above all — have no such context, and FastAPI's default
``{"detail": [...]}`` body with status 422 matches none of the mocked APIs: a
client parsing errors the way it parses the real vendor's would break here in a
way it never would in production.

This module maps a request path back to its vendor so those framework-level
failures can be answered in the same shape and with the same status code the
real API would use.
"""
from __future__ import annotations

from utils.cs_response import build_cs_error_response
from utils.es_response import build_es_error_response
from utils.graph_response import build_graph_error_response
from utils.mde_response import build_mde_error_response
from utils.sentinel.response import build_arm_error
from utils.splunk.response import build_splunk_error
from utils.xdr_response import build_xdr_error

# Longest prefix wins, so order matters.
_VENDOR_PREFIXES: tuple[tuple[str, str], ...] = (
    ("/web/api/v2.1", "s1"),
    ("/cs", "crowdstrike"),
    ("/mde", "mde"),
    ("/graph", "graph"),
    ("/xdr", "xdr"),
    ("/elastic", "elasticsearch"),
    ("/kibana", "kibana"),
    ("/splunk", "splunk"),
    ("/sentinel", "sentinel"),
)

_STATUS_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    429: "Too Many Requests",
    500: "Internal Server Error",
}

# Error code names used by the Microsoft-flavoured APIs.
_MS_CODES: dict[int, str] = {
    400: "BadRequest",
    401: "Unauthenticated",
    403: "Forbidden",
    404: "NotFound",
    409: "Conflict",
    429: "TooManyRequests",
    500: "InternalServerError",
}


def vendor_for_path(path: str) -> str:
    """Identify which mocked vendor a request path belongs to.

    Args:
        path: Request path, e.g. ``/cs/devices/queries/devices/v1``.

    Returns:
        Vendor key, defaulting to ``"s1"`` for paths outside a vendor mount.
    """
    for prefix, vendor in _VENDOR_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return vendor
    return "s1"


def build_vendor_error(vendor: str, status: int, message: str) -> dict:
    """Build an error body in the envelope the given vendor uses.

    Args:
        vendor:  Vendor key from :func:`vendor_for_path`.
        status:  HTTP status code being returned.
        message: Human-readable error description.

    Returns:
        Error body dict shaped like the real vendor's error response.
    """
    if vendor == "crowdstrike":
        return build_cs_error_response(status, message)
    if vendor == "mde":
        return build_mde_error_response(_MS_CODES.get(status, "Error"), message)
    if vendor == "graph":
        return build_graph_error_response(_MS_CODES.get(status, "Error"), message)
    if vendor == "sentinel":
        return build_arm_error(_MS_CODES.get(status, "Error"), message)
    if vendor == "xdr":
        return build_xdr_error(status, message)
    if vendor == "elasticsearch":
        return build_es_error_response(status, "illegal_argument_exception", message)
    if vendor == "kibana":
        return {
            "statusCode": status,
            "error": _STATUS_TITLES.get(status, "Error"),
            "message": message,
        }
    if vendor == "splunk":
        return build_splunk_error(status, message)

    # SentinelOne — codes follow the <status><domain>0 convention.
    title = _STATUS_TITLES.get(status, "Error")
    return {
        "errors": [{"code": status * 10000 + 10, "detail": message, "title": title}],
        "data": None,
    }
