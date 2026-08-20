"""Microsoft Defender for Endpoint Vulnerability (TVM) query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_machine_repo import mde_machine_repo
from repository.mde_vulnerability_repo import mde_vulnerability_repo
from utils.mde_odata import apply_odata_filter, apply_odata_orderby, apply_odata_select
from utils.mde_response import build_mde_list_response


def _machine_refs_for(vuln_id: str) -> list[dict]:
    """Return the machines affected by a vulnerability.

    The single source of truth for that association. ``exposedMachines`` was a
    free-floating random number from the seeder while the ``machineReferences``
    sub-resource computed membership round-robin, so the two disagreed on every
    record — including CVEs reporting zero exposed machines alongside four
    affected-machine references.
    """
    all_vulns = mde_vulnerability_repo.list_all()
    vuln_idx = next(
        (i for i, v in enumerate(all_vulns) if v.vulnerabilityId == vuln_id), -1,
    )
    if vuln_idx < 0 or not all_vulns:
        return []
    return [
        {
            "id": machine.machineId,
            "computerDnsName": machine.computerDnsName,
            "osPlatform": machine.osPlatform,
            "rbacGroupName": machine.rbacGroupName,
        }
        for i, machine in enumerate(mde_machine_repo.list_all())
        if i % len(all_vulns) == vuln_idx
    ]


def _with_exposed_count(record: dict) -> dict:
    """Overwrite ``exposedMachines`` with the real membership count."""
    record["exposedMachines"] = len(_machine_refs_for(record.get("vulnerabilityId", "")))
    return record


def list_vulnerabilities(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
    select: str | None,
) -> dict:
    """List vulnerabilities with OData filtering, ordering, and pagination.

    Args:
        filter_str: OData ``$filter`` expression, or None for all vulnerabilities.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.
        select:     Comma-separated field names (``$select``), or None.

    Returns:
        OData list response with paginated vulnerability records.
    """
    records = [_with_exposed_count(asdict(v)) for v in mde_vulnerability_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/vulnerabilities"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_vulnerability(vuln_id: str) -> dict | None:
    """Get a single vulnerability by its CVE ID.

    Args:
        vuln_id: The CVE ID (e.g. ``"CVE-2024-12345"``).

    Returns:
        Vulnerability dict, or None if not found.
    """
    vuln = mde_vulnerability_repo.get(vuln_id)
    if not vuln:
        return None
    return _with_exposed_count(asdict(vuln))


def get_vulnerability_machine_references(vuln_id: str) -> dict | None:
    """Get machines affected by a specific vulnerability.

    Returns a list of machine references for machines associated with
    the given vulnerability.

    Args:
        vuln_id: The CVE ID to look up.

    Returns:
        OData list response with machine reference records, or None if
        vulnerability not found.
    """
    vuln = mde_vulnerability_repo.get(vuln_id)
    if not vuln:
        return None
    return build_mde_list_response(_machine_refs_for(vuln_id))
