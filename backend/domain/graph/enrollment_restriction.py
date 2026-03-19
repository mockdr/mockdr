"""Domain dataclass for Microsoft Graph Enrollment Restriction entity."""
from dataclasses import dataclass


@dataclass
class GraphEnrollmentRestriction:
    """An Intune device enrollment configuration from Microsoft Graph.

    Maps to real Graph API
    ``/v1.0/deviceManagement/deviceEnrollmentConfigurations`` response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    odata_type: str = ""  # output as @odata.type
    priority: int = 0
    createdDateTime: str = ""  # noqa: N815
