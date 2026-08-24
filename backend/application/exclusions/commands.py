
from domain.exclusion import Exclusion
from repository.activity_repo import activity_repo
from repository.exclusion_repo import exclusion_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.serde import record_dict


class InvalidExclusionError(ValueError):
    """Raised when an exclusion body is not a shape S1 accepts."""


def create_exclusion(body: dict, user_id: str | None) -> dict:
    """Create and persist a new threat exclusion.

    Args:
        body: Request body; ``{"data": {...}, "filter": {...}}`` or flat dict.
        user_id: ID of the creating user, if authenticated.

    Returns:
        Dict with ``data`` as a single-element list containing the new exclusion.
    """
    payload = body.get("data") or body
    # S1 accepts a list under `data` for bulk creation. Calling .get() on
    # it raised AttributeError straight out of the handler as a 500.
    data = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(data, dict):
        msg = "data must be an object or a non-empty array of objects"
        raise InvalidExclusionError(msg)
    eid = new_id()
    exclusion = Exclusion(
        id=eid,
        type=data.get("type", "path"),
        value=data.get("value", ""),
        osType=data.get("osType", "any"),
        mode=data.get("mode", "suppress"),
        source=data.get("source", "user"),
        createdAt=utc_now(),
        updatedAt=utc_now(),
        userId=user_id or "",
        userName=data.get("userName", ""),
        scopeName=data.get("scopeName", "Global"),
        scopePath=data.get("scopePath", "Global"),
        description=data.get("description", ""),
        siteId=data.get("siteId", ""),
        scope=data.get("scope", {"tenant": True}),
    )
    exclusion_repo.save(exclusion)
    activity_repo.create(128, "Exclusion added", user_id=user_id, site_id=exclusion.siteId)
    return {"data": [record_dict(exclusion)]}


def update_exclusion(exclusion_id: str, body: dict, user_id: str | None) -> dict | None:
    """Update an existing exclusion by ID.

    Args:
        exclusion_id: The ID of the exclusion to update.
        body: Request body with fields to update (flat or wrapped in ``data``).
        user_id: ID of the updating user.

    Returns:
        Dict with ``data`` containing the updated exclusion, or ``None`` if not found.
    """
    existing = exclusion_repo.get(exclusion_id)
    if existing is None:
        return None
    payload = body.get("data") or body
    # S1 accepts a list under `data` for bulk creation. Calling .get() on
    # it raised AttributeError straight out of the handler as a 500.
    data = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(data, dict):
        msg = "data must be an object or a non-empty array of objects"
        raise InvalidExclusionError(msg)
    updatable = (
        "type", "value", "osType", "mode", "source", "description",
        "scopeName", "scopePath", "scope", "actions", "pathExclusionType",
        "applicationName", "includeChildren", "includeParents",
    )
    for key in updatable:
        if key in data:
            setattr(existing, key, data[key])
    existing.updatedAt = utc_now()
    exclusion_repo.save(existing)
    activity_repo.create(129, "Exclusion updated", user_id=user_id, site_id=existing.siteId)
    return {"data": record_dict(existing)}


def delete_exclusion(exclusion_id: str, user_id: str | None = None) -> dict:
    """Delete an exclusion by ID.

    Args:
        exclusion_id: The ID of the exclusion to delete.
        user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` (1 if deleted, 0 if not found).
    """
    existing = exclusion_repo.get(exclusion_id)
    site_id = existing.siteId if existing else None
    deleted = exclusion_repo.delete(exclusion_id)
    if deleted:
        activity_repo.create(130, "Exclusion deleted", user_id=user_id, site_id=site_id)
    return {"data": {"affected": 1 if deleted else 0}}
