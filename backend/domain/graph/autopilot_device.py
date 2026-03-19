"""Domain dataclass for Microsoft Graph Autopilot Device Identity."""
from dataclasses import dataclass


@dataclass
class GraphAutopilotDevice:
    """A Windows Autopilot device identity from Microsoft Graph.

    Maps 1:1 to real Graph API
    ``/v1.0/deviceManagement/windowsAutopilotDeviceIdentities`` response
    fields.  Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    serialNumber: str = ""  # noqa: N815
    manufacturer: str = ""
    model: str = ""
    groupTag: str = ""  # noqa: N815
    purchaseOrderIdentifier: str = ""  # noqa: N815
    enrollmentState: str = "notContacted"  # noqa: N815 — notContacted, enrolled, pendingReset
    lastContactedDateTime: str = ""  # noqa: N815
    deploymentProfileAssignmentStatus: str = "notAssigned"  # noqa: N815 — assigned, notAssigned, pending
