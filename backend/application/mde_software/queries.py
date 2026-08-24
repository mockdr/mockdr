"""Microsoft Defender for Endpoint Software (TVM) query handlers (read-only)."""
from __future__ import annotations

from repository.mde_machine_repo import mde_machine_repo
from repository.mde_software_repo import mde_software_repo
from utils.mde_fixtures import complete_mde
from utils.mde_odata import apply_odata_filter, apply_odata_orderby, apply_odata_select
from utils.mde_response import build_mde_list_response
from utils.serde import record_dict


def _machine_refs_for(software_id: str) -> list[dict]:
    """Return the machines associated with a software entry.

    The single source of truth for that association. ``exposedMachines`` was a
    free-floating random number from the seeder while the ``machineReferences``
    sub-resource computed membership round-robin, so the count and the list
    disagreed on every record — including entries reporting zero exposed
    machines alongside four references.
    """
    all_software = mde_software_repo.list_all()
    sw_idx = next(
        (i for i, s in enumerate(all_software) if s.softwareId == software_id), -1,
    )
    if sw_idx < 0 or not all_software:
        return []
    return [
        {
            "id": machine.machineId,
            "computerDnsName": machine.computerDnsName,
            "osPlatform": machine.osPlatform,
            "rbacGroupName": machine.rbacGroupName,
        }
        for i, machine in enumerate(mde_machine_repo.list_all())
        if i % len(all_software) == sw_idx
    ]


def _with_exposed_count(record: dict) -> dict:
    """Overwrite ``exposedMachines`` with the real membership count."""
    record["exposedMachines"] = len(_machine_refs_for(record.get("softwareId", "")))
    return complete_mde(record, "software")


def list_software(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
    select: str | None,
) -> dict:
    """List software inventory with OData filtering, ordering, and pagination.

    Args:
        filter_str: OData ``$filter`` expression, or None for all software.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.
        select:     Comma-separated field names (``$select``), or None.

    Returns:
        OData list response with paginated software records.
    """
    records = [_with_exposed_count(record_dict(s)) for s in mde_software_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/software"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_software(software_id: str) -> dict | None:
    """Get a single software entry by its software ID.

    Args:
        software_id: The software ID in ``vendor-_-product`` format.

    Returns:
        Software dict, or None if not found.
    """
    software = mde_software_repo.get(software_id)
    if not software:
        return None
    return _with_exposed_count(record_dict(software))


def get_software_machine_references(software_id: str) -> dict | None:
    """Get machines that have a specific software installed.

    Returns a list of machine references (ID + DNS name) for machines
    associated with the given software.

    Args:
        software_id: The software ID to look up.

    Returns:
        OData list response with machine reference records, or None if
        software not found.
    """
    software = mde_software_repo.get(software_id)
    if not software:
        return None
    return build_mde_list_response(_machine_refs_for(software_id))
