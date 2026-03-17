"""Microsoft Defender for Endpoint Software (TVM) query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_machine_repo import mde_machine_repo
from repository.mde_software_repo import mde_software_repo
from utils.mde_odata import apply_odata_filter, apply_odata_orderby, apply_odata_select
from utils.mde_response import build_mde_list_response


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
    records = [asdict(s) for s in mde_software_repo.list_all()]
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
    return asdict(software)


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
    # Associate software with machines round-robin by index
    all_software = mde_software_repo.list_all()
    sw_idx = next(
        (i for i, s in enumerate(all_software) if s.softwareId == software_id), -1,
    )
    machines = mde_machine_repo.list_all()
    refs = []
    for i, machine in enumerate(machines):
        if len(all_software) > 0 and i % len(all_software) == sw_idx:
            refs.append({
                "id": machine.machineId,
                "computerDnsName": machine.computerDnsName,
                "osPlatform": machine.osPlatform,
                "rbacGroupName": machine.rbacGroupName,
            })
    return build_mde_list_response(refs)
