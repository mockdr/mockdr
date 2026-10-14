"""Microsoft Defender for Endpoint API response envelope builders.

MDE uses OData v4 conventions:
- List endpoints return ``{"@odata.context": "...", "value": [...]}``
- Single entities are returned as bare dicts (no envelope)
- Errors use ``{"error": {"code": "...", "message": "..."}}``
"""
from __future__ import annotations

import uuid

#: Stable namespace for deriving the tracking GUID, so identical errors
#: report an identical target across runs.
_TARGET_NAMESPACE = uuid.UUID("6f1a3d52-0c2e-4a7f-9b8d-2c5e7a1f4b30")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

#: The host Defender's API pages now show in every response example.
_CONTEXT_BASE = "https://api.security.microsoft.com/api/$metadata"


def mde_context(entity_set: str) -> str:
    """The ``@odata.context`` of a Defender collection, e.g. ``...#Machines``.

    Every list example on learn.microsoft.com/en-us/defender-endpoint/api/
    names its entity set -- ``$metadata#Machines``, ``#Alerts``,
    ``#Indicators``, ``#MachineActions``, ``#Software``,
    ``#Vulnerabilities``, ``#Investigations``, ``#MachineReferences`` -- on
    ``api.security.microsoft.com``. The mock answered the bare
    ``$metadata`` on the legacy host for all of them, so a client that reads
    the context to tell one collection from another (OData clients do) could
    not.
    """
    return f"{_CONTEXT_BASE}#{entity_set}"


def build_mde_list_response(
    value: list[dict],
    context: str = "https://api.securitycenter.microsoft.com/api/$metadata",
    next_link: str | None = None,
    count: int | None = None,
) -> dict:
    """Build an OData v4 list response envelope.

    Args:
        value:     Page of resource objects.
        context:   OData context URL (cosmetic).
        next_link: Optional ``@odata.nextLink`` for pagination.
        count:     Total record count, emitted as ``@odata.count`` when
                   ``$count=true`` was requested.

    Returns:
        OData list response dict.
    """
    resp: dict = {"@odata.context": context, "value": value}
    if count is not None:
        resp["@odata.count"] = count
    if next_link:
        resp["@odata.nextLink"] = next_link
    return resp


def build_mde_error_response(code: str, message: str, target: str | None = None) -> dict:
    """Build an MDE-style error response.

    Defender's error envelope carries a third member the other Microsoft APIs
    do not: ``target``, which is a per-response tracking GUID rather than the
    OData "which field was wrong" pointer the name suggests. Support articles
    ask for it by name, so a client that surfaces it has nothing to show if the
    mock omits it.

    The GUID is derived from the error rather than drawn fresh: mockdr promises
    repeatable responses, and a random value here would make two identical
    requests differ, defeating snapshot comparison and recorded replay for the
    one field a caller is least likely to think to exclude.

    Args:
        code:    Error code string (e.g. ``"ResourceNotFound"``).
        message: Human-readable error description.
        target:  Tracking identifier; derived from *code* and *message* when
                 not supplied.

    Returns:
        MDE error envelope dict.
    """
    return {
        "error": {
            "code": code,
            "message": message,
            "target": target or str(uuid.uuid5(_TARGET_NAMESPACE, f"{code}:{message}")),
        },
    }
