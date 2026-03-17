from dataclasses import asdict

from domain.ioc import IOC
from repository.activity_repo import activity_repo
from repository.ioc_repo import ioc_repo
from utils.dt import utc_now
from utils.id_gen import new_id


def create_ioc(body: dict) -> dict:
    """Create and persist a single IOC.

    Args:
        body: Request body fields (already unwrapped from ``{"data": {...}}`` envelope).

    Returns:
        Dict with ``data`` containing the serialised new IOC.
    """
    ioc_uuid = new_id()
    ioc = IOC(
        uuid=ioc_uuid,
        type=body.get("type", "SHA1"),
        value=body.get("value", ""),
        name=body.get("name"),
        description=body.get("description"),
        source=body.get("source", "user"),
        externalId=body.get("externalId"),
        validUntil=body.get("validUntil"),
        creationTime=utc_now(),
        updatedAt=utc_now(),
    )
    ioc_repo.save(ioc)
    activity_repo.create(
        activity_type=4001,
        description=f"IOC created: {ioc.type} = {ioc.value}",
    )
    return {"data": asdict(ioc)}


def bulk_create_iocs(items: list[dict]) -> dict:
    """Create multiple IOCs from a list of dicts.

    Args:
        items: List of IOC body dicts, each passed to ``create_ioc``.

    Returns:
        Dict with ``data.affected`` indicating how many IOCs were created.
    """
    created = 0
    for item in items:
        create_ioc(item)
        created += 1
    return {"data": {"affected": created}}


def delete_iocs(ioc_ids: list[str]) -> dict:
    """Delete a list of IOCs by uuid.

    Args:
        ioc_ids: List of IOC uuids to delete.

    Returns:
        Dict with ``data.affected`` indicating how many IOCs were deleted.
    """
    affected = 0
    for iid in ioc_ids:
        if ioc_repo.delete(iid):
            activity_repo.create(
                activity_type=4002,
                description=f"IOC deleted: {iid}",
            )
            affected += 1
    return {"data": {"affected": affected}}
