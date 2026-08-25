"""CrowdStrike Falcon Custom IOC command handlers (mutations)."""
from __future__ import annotations

import uuid as _uuid

from domain.cs_ioc import CsIoc
from repository.cs_ioc_repo import cs_ioc_repo
from utils.cs_response import build_cs_action_response, build_cs_entity_response
from utils.dt import utc_now
from utils.serde import record_dict


def create_iocs(indicators: list[dict]) -> dict:
    """Create one or more custom IOCs from raw dicts.

    Each dict should contain at minimum ``type``, ``value``, and ``action``.
    Missing fields are filled with sensible defaults.

    Args:
        indicators: List of indicator dicts to create.

    Returns:
        CS entity response containing the newly created IOC entities.
    """
    created: list[dict] = []
    now = utc_now()
    for raw in indicators:
        ioc = CsIoc(
            id=raw.get("id", str(_uuid.uuid4())),
            type=raw.get("type", ""),
            value=raw.get("value", ""),
            source=raw.get("source", "api"),
            action=raw.get("action", "no_action"),
            severity=raw.get("severity", "informational"),
            description=raw.get("description", ""),
            platforms=raw.get("platforms", []),
            tags=raw.get("tags", []),
            applied_globally=raw.get("applied_globally", True),
            host_groups=raw.get("host_groups", []),
            expiration=raw.get("expiration", ""),
            mobile_action=raw.get("mobile_action", ""),
            created_on=now,
            created_by=raw.get("created_by", "api-client"),
            modified_on=now,
            modified_by=raw.get("modified_by", "api-client"),
        )
        cs_ioc_repo.save(ioc)
        created.append(record_dict(ioc))
    return build_cs_entity_response(created)


def update_iocs(indicators: list[dict]) -> dict:
    """Update every IOC named in ``indicators``.

    Each member carries the ``id`` of the indicator to change; only the
    fields present are overwritten, and one that does not resolve is left
    out of the answer rather than failing the call.

    Args:
        indicators: ``APIIndicatorUpdateReqsV1.indicators``.

    Returns:
        CS entity response with every IOC that was updated.
    """
    updatable = (
        "action", "severity", "description", "platforms", "tags",
        "applied_globally", "host_groups", "expiration", "mobile_action",
        "source",
    )
    updated = []
    for body in indicators:
        ioc = cs_ioc_repo.get(body.get("id", ""))
        if not ioc:
            continue
        for field_name in updatable:
            if field_name in body:
                setattr(ioc, field_name, body[field_name])
        ioc.modified_on = utc_now()
        ioc.modified_by = body.get("modified_by", "api-client")
        cs_ioc_repo.save(ioc)
        updated.append(record_dict(ioc))
    return build_cs_entity_response(updated)


def delete_iocs(ids: list[str]) -> dict:
    """Delete IOCs by ID list.

    Args:
        ids: List of IOC IDs to delete.

    Returns:
        CS action response with affected IOC IDs.
    """
    affected: list[dict] = []
    for ioc_id in ids:
        if cs_ioc_repo.delete(ioc_id):
            affected.append({"id": ioc_id})
    return build_cs_action_response(affected)
