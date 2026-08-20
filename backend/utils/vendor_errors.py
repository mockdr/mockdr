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
from utils.es_response import build_es_error_response, build_kbn_error_response
from utils.graph_response import build_graph_error_response
from utils.mde_response import build_mde_error_response
from utils.sentinel.response import build_arm_error
from utils.splunk.response import build_hec_error, build_splunk_error
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
    # HEC is a different service from splunkd with a different error shape, and
    # it sits under the same mount — longest prefix wins, so it goes first.
    ("/splunk/services/collector", "splunk_hec"),
    ("/splunk", "splunk"),
    ("/sentinel", "sentinel"),
)

_STATUS_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    429: "Too Many Requests",
    500: "Internal Server Error",
}

# The three Microsoft-flavoured APIs share an envelope but NOT their code
# strings, so one table for all of them put the wrong code in two of the three.
# Each of these is the string the vendor documents for that status.

#: Elasticsearch derives its ``type`` from the Java exception class, so it names
#: the failure rather than the status — one type for every status told a client
#: an auth rejection was a bad argument. ``security_exception`` covers both 401
#: and 403; only ``status`` separates them.
_ES_TYPES: dict[int, str] = {
    400: "illegal_argument_exception",
    401: "security_exception",
    403: "security_exception",
    # Not index_not_found_exception: that names a *missing index* and carries
    # `index`/`index_uuid` members clients read, which a routing 404 has no
    # values for. build_es_index_not_found covers the index case properly.
    404: "resource_not_found_exception",
    429: "circuit_breaking_exception",
    500: "exception",
}

#: SentinelOne writes its own wording into ``title`` rather than reusing the
#: HTTP reason phrase, so a client keying off the title sees a different string
#: from the generic one. Values observed on real tenants.
_S1_TITLES: dict[int, str] = {
    400: "Validation Error",
    401: "Authentication Failed",
    403: "Insufficient permissions",
    404: "Requested resource was not found",
    501: "Not supported",
}

#: Defender for Endpoint — learn.microsoft.com/defender-endpoint/api/common-errors
_MDE_CODES: dict[int, str] = {
    400: "BadRequest",
    401: "Unauthorized",
    403: "Forbidden",
    404: "ResourceNotFound",
    405: "BadRequest",
    409: "Conflict",
    429: "TooManyRequests",
    500: "InternalServerError",
}

#: Microsoft Graph. Graph is not internally consistent — directory endpoints use
#: ``Underscore_Case`` while the files workload uses ``camelCase`` — so these are
#: the directory-flavoured codes, which is what the mocked surface serves.
_GRAPH_CODES: dict[int, str] = {
    400: "badRequest",
    401: "InvalidAuthenticationToken",
    403: "Authorization_RequestDenied",
    404: "Request_ResourceNotFound",
    405: "badRequest",
    409: "Request_BadRequest",
    429: "TooManyRequests",
    500: "generalException",
}

#: Azure Resource Manager, which Sentinel sits behind.
_ARM_CODES: dict[int, str] = {
    400: "BadRequest",
    401: "AuthenticationFailed",
    403: "AuthorizationFailed",
    404: "ResourceNotFound",
    405: "BadRequest",
    409: "Conflict",
    429: "TooManyRequests",
    500: "InternalServerError",
}


def vendor_mount_for_path(path: str) -> str | None:
    """Identify the vendor mount a request path falls under, if any.

    Args:
        path: Request path, e.g. ``/cs/devices/queries/devices/v1``.

    Returns:
        Vendor key, or ``None`` when the path is outside every vendor mount —
        which :func:`vendor_for_path` cannot express, because it has to answer
        with *some* vendor for the error envelope.
    """
    for prefix, vendor in _VENDOR_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return vendor
    return None


def vendor_for_path(path: str) -> str:
    """Identify which mocked vendor a request path belongs to.

    Args:
        path: Request path, e.g. ``/cs/devices/queries/devices/v1``.

    Returns:
        Vendor key, defaulting to ``"s1"`` for paths outside a vendor mount.
    """
    return vendor_mount_for_path(path) or "s1"


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
        return build_mde_error_response(_MDE_CODES.get(status, "InternalServerError"), message)
    if vendor == "graph":
        return build_graph_error_response(_GRAPH_CODES.get(status, "generalException"), message)
    if vendor == "sentinel":
        return build_arm_error(_ARM_CODES.get(status, "InternalServerError"), message)
    if vendor == "xdr":
        return build_xdr_error(status, message)
    if vendor == "elasticsearch":
        return build_es_error_response(status, _ES_TYPES.get(status, "exception"), message)
    if vendor == "kibana":
        return build_kbn_error_response(status, message)
    if vendor == "splunk_hec":
        return build_hec_error(status, message)
    if vendor == "splunk":
        return build_splunk_error(status, message)

    # SentinelOne — codes follow the <status><domain>0 convention, and the body
    # carries no `data` key: the schemas backing every error status in S1's own
    # Swagger are named `_NoDataSchema_<status>` and declare `errors` alone.
    return {
        "errors": [
            {
                "code": status * 10000 + 10,
                "detail": message,
                "title": _S1_TITLES.get(status, _STATUS_TITLES.get(status, "Error")),
            },
        ],
    }
