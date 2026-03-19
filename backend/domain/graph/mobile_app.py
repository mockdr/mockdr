"""Domain dataclass for Microsoft Graph Mobile App entity."""
from dataclasses import dataclass


@dataclass
class GraphMobileApp:
    """An Intune mobile app from Microsoft Graph.

    Maps to real Graph API
    ``/v1.0/deviceAppManagement/mobileApps`` response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    publisher: str = ""
    odata_type: str = ""  # output as @odata.type
    isFeatured: bool = False  # noqa: N815
    privacyInformationUrl: str | None = None  # noqa: N815
    installCommandLine: str | None = None  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    lastModifiedDateTime: str = ""  # noqa: N815
