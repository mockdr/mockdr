"""Domain dataclass for Microsoft Graph App Protection Policy entity."""
from dataclasses import dataclass, field


@dataclass
class GraphAppProtectionPolicy:
    """An Intune app protection (MAM) policy from Microsoft Graph.

    Maps to real Graph API
    ``/v1.0/deviceAppManagement/managedAppPolicies`` response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    odata_type: str = ""  # output as @odata.type
    pinRequired: bool = True  # noqa: N815
    minimumPinLength: int = 4  # noqa: N815
    allowedDataStorageLocations: list[str] = field(default_factory=list)  # noqa: N815
    dataBackupBlocked: bool = True  # noqa: N815
    organizationalCredentialsRequired: bool = False  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    lastModifiedDateTime: str = ""  # noqa: N815
    version: str = "1"
