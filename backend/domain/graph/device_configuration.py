"""Domain dataclass for Microsoft Graph Device Configuration entity."""
from dataclasses import dataclass


@dataclass
class GraphDeviceConfiguration:
    """An Intune device configuration profile from Microsoft Graph.

    Maps 1:1 to real Graph API
    ``/v1.0/deviceManagement/deviceConfigurations`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    odata_type: str = ""  # output as @odata.type
    createdDateTime: str = ""  # noqa: N815
    lastModifiedDateTime: str = ""  # noqa: N815
    version: int = 1
