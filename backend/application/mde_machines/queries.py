"""Microsoft Defender for Endpoint Machine query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_alert_repo import mde_alert_repo
from repository.mde_machine_repo import mde_machine_repo
from repository.mde_vulnerability_repo import mde_vulnerability_repo
from utils.mde_odata import apply_odata_filter, apply_odata_orderby, apply_odata_select
from utils.mde_response import build_mde_list_response


def list_machines(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
    select: str | None,
) -> dict:
    """List machines with OData filtering, ordering, selection, and pagination.

    Args:
        filter_str: OData ``$filter`` expression, or None for all machines.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.
        select:     Comma-separated field names (``$select``), or None.

    Returns:
        OData list response with paginated machine records.
    """
    records = [asdict(m) for m in mde_machine_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/machines"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_machine(machine_id: str) -> dict | None:
    """Get a single machine by its machine ID.

    Args:
        machine_id: The GUID of the machine to retrieve.

    Returns:
        Machine dict, or None if not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    return asdict(machine)


def get_machine_logon_users(machine_id: str) -> dict | None:
    """Get logon users for a specific machine.

    Args:
        machine_id: The GUID of the machine.

    Returns:
        OData list response with logon user records, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    return build_mde_list_response(machine.loggedOnUsers)


def get_machine_alerts(machine_id: str) -> dict | None:
    """Get alerts associated with a specific machine.

    Args:
        machine_id: The GUID of the machine.

    Returns:
        OData list response with alert records, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    alerts = mde_alert_repo.get_by_machine_id(machine_id)
    return build_mde_list_response([asdict(a) for a in alerts])


def _get_agent_id_for_machine(machine_id: str) -> str | None:
    """Find the S1 agent_id mapped to this MDE machine_id via edr_id_map."""
    from repository.store import store
    all_maps = store._collections["edr_id_map"]  # noqa: SLF001
    for agent_id, mapping in all_maps.items():
        if isinstance(mapping, dict) and mapping.get("mde_machine_id") == machine_id:
            return agent_id
    return None


def _make_software_id(vendor: str, name: str) -> str:
    """Build MDE-style software ID (``vendor-_-product``)."""
    v = vendor.lower().replace(" ", "_").replace(",", "").replace(".", "")
    n = name.lower().replace(" ", "_").replace(",", "").replace(".", "")
    return f"{v}-_-{n}"


def _app_to_mde_software(app: dict) -> dict:
    """Transform a canonical installed_app to MDE TVM software format."""
    name = app.get("name", "")
    vendor = app.get("publisher", app.get("publisherName", ""))
    return {
        "id": _make_software_id(vendor, name),
        "name": name,
        "vendor": vendor,
        "version": app.get("version", ""),
        "weaknesses": 0,
        "publicExploit": False,
        "activeAlert": False,
        "exposedMachines": 1,
        "impactScore": 0.0,
    }


def get_machine_software(machine_id: str) -> dict | None:
    """Get software installed on a specific machine.

    Uses the canonical ``installed_apps`` store via the ``edr_id_map``
    to provide the same app inventory as S1 and CS, translated to MDE
    TVM software format.

    Args:
        machine_id: The GUID of the machine.

    Returns:
        OData list response with software records, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None

    agent_id = _get_agent_id_for_machine(machine_id)
    if not agent_id:
        return build_mde_list_response([])

    from repository.store import store
    all_apps = store.get_all("installed_apps")
    machine_apps = [a for a in all_apps if a.get("agentId") == agent_id]

    software = [_app_to_mde_software(app) for app in machine_apps]
    return build_mde_list_response(software)


def get_software_inventory_export() -> dict:
    """Return the full software inventory export across all machines.

    Returns data inline matching the MDE ``SoftwareInventoryByMachine``
    response format.  For the mock, we return an ``exportFiles`` array
    containing a single URL pointing to the inline export endpoint.
    """
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#ExportFilesResponse",
        "exportFiles": [
            "/_mock/mde/software-export-data.json",
        ],
        "generatedTime": __import__("datetime").datetime.now(
            __import__("datetime").UTC,
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def get_software_export_data() -> list[dict]:
    """Return the full software inventory export as a flat list.

    Each record includes ``deviceId``, ``deviceName``, ``softwareVendor``,
    ``softwareName``, ``softwareVersion``, and ``osPlatform``.
    """
    from repository.agent_repo import agent_repo
    from repository.store import store

    all_maps = store._collections["edr_id_map"]  # noqa: SLF001
    all_apps = store.get_all("installed_apps")

    agent_info: dict[str, dict] = {}
    for agent in agent_repo.list_all():
        mapping = all_maps.get(agent.id, {})
        mde_id = mapping.get("mde_machine_id") if isinstance(mapping, dict) else None
        if mde_id:
            agent_info[agent.id] = {
                "mde_machine_id": mde_id,
                "hostname": agent.computerName,
                "os_platform": agent.osType,
            }

    records: list[dict] = []
    for app in all_apps:
        agent_id = app.get("agentId", "")
        info = agent_info.get(agent_id)
        if not info:
            continue
        records.append({
            "deviceId": info["mde_machine_id"],
            "deviceName": info["hostname"],
            "osPlatform": info["os_platform"],
            "softwareVendor": app.get("publisher", app.get("publisherName", "")),
            "softwareName": app.get("name", ""),
            "softwareVersion": app.get("version", ""),
            "numberOfWeaknesses": 0,
            "diskPaths": [],
            "registryPaths": [],
            "softwareFirstSeenTimestamp": app.get("installedDate", ""),
            "endOfSupportStatus": "",
            "endOfSupportDate": None,
        })

    return records


def get_machine_vulnerabilities(machine_id: str) -> dict | None:
    """Get vulnerabilities affecting a specific machine via its installed software.

    Args:
        machine_id: The GUID of the machine.

    Returns:
        OData list response with vulnerability records, or None if machine
        not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    all_vulns = [asdict(v) for v in mde_vulnerability_repo.list_all()]
    machines = mde_machine_repo.list_all()
    machine_idx = next(
        (i for i, m in enumerate(machines) if m.machineId == machine_id), -1,
    )
    if machine_idx < 0:
        return build_mde_list_response([])
    associated = [
        v for i, v in enumerate(all_vulns) if i % len(machines) == machine_idx
    ] if machines else []
    return build_mde_list_response(associated)


def get_machine_recommendations(machine_id: str) -> dict | None:
    """Get security recommendations for a specific machine.

    Returns canned security recommendations matching MDE API format.

    Args:
        machine_id: The GUID of the machine.

    Returns:
        OData list response with recommendation records, or None if machine
        not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    recommendations = [
        {
            "id": f"rec-{machine_id[:8]}-001",
            "productName": "Windows 10",
            "recommendationName": "Update operating system",
            "weaknesses": 3,
            "vendor": "microsoft",
            "recommendedVersion": "22H2",
            "recommendationCategory": "Application",
            "subCategory": "OS",
            "severityScore": 7.5,
            "publicExploit": False,
            "activeAlert": False,
            "associatedThreats": [],
            "remediationType": "Update",
            "status": "Active",
            "configScoreImpact": 2.0,
            "exposureImpact": 3.0,
            "totalMachineCount": 1,
            "exposedMachinesCount": 1,
            "nonProductivityImpactedAssets": 0,
            "relatedComponent": "OS",
        },
        {
            "id": f"rec-{machine_id[:8]}-002",
            "productName": "Microsoft Edge",
            "recommendationName": "Update browser to latest version",
            "weaknesses": 1,
            "vendor": "microsoft",
            "recommendedVersion": "120.0",
            "recommendationCategory": "Application",
            "subCategory": "Browser",
            "severityScore": 5.0,
            "publicExploit": False,
            "activeAlert": False,
            "associatedThreats": [],
            "remediationType": "Update",
            "status": "Active",
            "configScoreImpact": 1.0,
            "exposureImpact": 1.5,
            "totalMachineCount": 1,
            "exposedMachinesCount": 1,
            "nonProductivityImpactedAssets": 0,
            "relatedComponent": "Browser",
        },
    ]
    return build_mde_list_response(recommendations)
