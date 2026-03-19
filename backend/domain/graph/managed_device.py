"""Domain dataclass for Microsoft Graph Managed Device entity."""
from dataclasses import dataclass, field


@dataclass
class GraphManagedDevice:
    """An Intune-managed device from Microsoft Graph.

    Maps 1:1 to real Graph API ``/v1.0/deviceManagement/managedDevices``
    response fields.  Field names use camelCase to match the Graph API JSON
    format.
    """
    id: str  # noqa: A003 — GUID
    deviceName: str = ""  # noqa: N815
    operatingSystem: str = ""  # noqa: N815
    osVersion: str = ""  # noqa: N815
    lastSyncDateTime: str = ""  # noqa: N815
    complianceState: str = "compliant"  # compliant | noncompliant | unknown  # noqa: N815
    managementState: str = "managed"  # noqa: N815
    managedDeviceOwnerType: str = "company"  # noqa: N815
    enrolledDateTime: str = ""  # noqa: N815
    userPrincipalName: str = ""  # noqa: N815
    model: str = ""
    manufacturer: str = ""
    serialNumber: str = ""  # noqa: N815
    deviceActionResults: list[dict] = field(default_factory=list)  # noqa: N815
