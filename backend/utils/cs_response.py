"""CrowdStrike API response envelope builders.

CrowdStrike uses a different response format from SentinelOne.  Every response
includes a ``meta`` block with ``query_time``, ``powered_by``, and ``trace_id``,
plus ``resources`` and ``errors`` arrays.
"""
from __future__ import annotations

import uuid

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_meta(
    query_time: float = 0.01,
    pagination: dict | None = None,
) -> dict:
    """Build the ``meta`` block common to all CrowdStrike responses.

    Args:
        query_time: Simulated query time in seconds.
        pagination: Optional pagination sub-object.

    Returns:
        Meta dict with ``query_time``, ``powered_by``, ``trace_id``, and
        optionally ``pagination``.
    """
    meta: dict = {
        "query_time": query_time,
        "powered_by": "crowdstrike-api",
        "trace_id": str(uuid.uuid4()),
    }
    if pagination is not None:
        meta["pagination"] = pagination
    return meta


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_cs_list_response(
    resources: list,
    total: int,
    offset: int = 0,
    limit: int = 100,
    query_time: float = 0.01,
) -> dict:
    """Build a CrowdStrike API list response with pagination metadata.

    Args:
        resources: Page of resource objects to include.
        total:     Total number of matching resources across all pages.
        offset:    Current page offset.
        limit:     Page size limit.
        query_time: Simulated query time in seconds.

    Returns:
        Complete CrowdStrike response envelope with pagination.
    """
    return {
        "meta": _build_meta(
            query_time=query_time,
            pagination={"offset": offset, "limit": limit, "total": total},
        ),
        "resources": resources,
        "errors": [],
    }


def build_cs_id_response(
    ids: list[str],
    total: int,
    offset: int = 0,
    limit: int = 100,
) -> dict:
    """Build a CrowdStrike API ID query response (for ``/queries/`` endpoints).

    Args:
        ids:    Page of resource ID strings.
        total:  Total number of matching IDs across all pages.
        offset: Current page offset.
        limit:  Page size limit.

    Returns:
        Complete CrowdStrike response envelope with ID resources.
    """
    return {
        "meta": _build_meta(
            pagination={"offset": offset, "limit": limit, "total": total},
        ),
        "resources": ids,
        "errors": [],
    }


def build_cs_entity_response(resources: list) -> dict:
    """Build a CrowdStrike API entity response (for ``/entities/`` endpoints).

    Args:
        resources: Full entity objects to return.

    Returns:
        Complete CrowdStrike response envelope without pagination.
    """
    return {
        "meta": _build_meta(),
        "resources": resources,
        "errors": [],
    }


def build_cs_action_response(resources: list | None = None) -> dict:
    """Build a CrowdStrike API action response.

    Args:
        resources: Optional list of affected resource objects.  Defaults to
                   an empty list.

    Returns:
        Complete CrowdStrike response envelope for action endpoints.
    """
    return {
        "meta": _build_meta(),
        "resources": resources if resources is not None else [],
        "errors": [],
    }


def build_cs_error_response(code: int, message: str) -> dict:
    """Build a CrowdStrike API error response.

    Args:
        code:    HTTP status code (also used as the error code).
        message: Human-readable error description.

    Returns:
        CrowdStrike error envelope with empty resources.
    """
    return {
        "meta": _build_meta(query_time=0.0),
        "errors": [{"code": code, "message": message}],
        "resources": [],
    }
