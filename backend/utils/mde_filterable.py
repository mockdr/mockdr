"""Which properties each Defender collection lets ``$filter`` name.

"Not all properties are filterable"
(https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-odata-samples),
and each collection's page lists the ones that are, under "$filter on the
following properties". The mock filtered on anything the record carried, so a
client could build a query -- ``osBuild gt 19000``, ``machineId eq '...'`` on
alerts -- that the product refuses, and only find out in production.

Names compare case-insensitively: the pages themselves are not consistent
(``InvestigationId`` beside ``incidentId``, ``ComputerDnsName`` on the
samples page and ``computerDnsName`` on get-machines), and refusing a real
property over a docs casing slip is the worse error. ``asssignedTo`` on
get-alerts is taken as the typo it is.
"""
from __future__ import annotations

from fastapi import HTTPException

from utils.mde_odata import ODataNode, parse_odata_filter
from utils.mde_response import build_mde_error_response

#: Per collection, from the page named beside it on
#: learn.microsoft.com/en-us/defender-endpoint/api/.
FILTERABLE: dict[str, frozenset[str]] = {
    # get-machines
    "machines": frozenset({
        "computerDnsName", "id", "version", "deviceValue", "aadDeviceId", "machineTags",
        "lastSeen", "exposureLevel", "onboardingStatus", "lastIpAddress", "healthStatus",
        "osPlatform", "riskScore", "rbacGroupId",
    }),
    # get-alerts
    "alerts": frozenset({
        "alertCreationTime", "lastUpdateTime", "incidentId", "investigationId", "id",
        "assignedTo", "detectionSource", "lastEventTime", "status", "severity", "category",
    }),
    # get-ti-indicators-collection
    "indicators": frozenset({
        "application", "createdByDisplayName", "expirationTime", "generateAlert", "title",
        "rbacGroupNames", "rbacGroupIds", "indicatorValue", "indicatorType",
        "creationTimeDateTimeUtc", "createdBy", "action", "severity",
    }),
    # get-machineactions-collection
    "machineactions": frozenset({
        "id", "status", "machineId", "type", "requestor", "creationDateTimeUtc",
    }),
    # get-software
    "software": frozenset({"id", "name", "vendor"}),
    # get-all-vulnerabilities
    "vulnerabilities": frozenset({
        "id", "name", "description", "cvssV3", "publishedOn", "severity", "updatedOn",
    }),
    # get-investigation-collection
    "investigations": frozenset({
        "startTime", "id", "state", "machineId", "triggeringAlertId",
    }),
}


def _fields(node: ODataNode | None) -> set[str]:
    """Every property a parsed filter names."""
    if node is None:
        return set()
    field = getattr(node, "field", None)
    if isinstance(field, str):
        return {field}
    found: set[str] = set()
    for child in getattr(node, "children", ()):
        found |= _fields(child)
    return found


def refuse_unfilterable(filter_str: str | None, collection: str) -> None:
    """Refuse a ``$filter`` naming a property the collection does not filter on.

    A filter that does not parse is left to the filter engine, which refuses
    it with its own message.

    Raises:
        HTTPException: 400 ``ODataError`` -- "Invalid OData URI query (the
            specific error is specified)" in
            https://learn.microsoft.com/en-us/defender-endpoint/api/common-errors.
    """
    if not filter_str or not filter_str.strip():
        return
    try:
        named = _fields(parse_odata_filter(filter_str))
    except ValueError:
        return
    allowed = {name.lower() for name in FILTERABLE[collection]}
    for name in sorted(named):
        if name.lower() not in allowed:
            raise HTTPException(status_code=400, detail=build_mde_error_response(
                "ODataError",
                f"Invalid OData URI query: the property '{name}' cannot be used in the "
                f"$filter query option.",
            ))
