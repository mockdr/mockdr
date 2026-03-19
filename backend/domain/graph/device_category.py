"""Domain dataclass for Microsoft Graph Device Category entity."""
from dataclasses import dataclass


@dataclass
class GraphDeviceCategory:
    """An Intune device category from Microsoft Graph.

    Maps to real Graph API
    ``/v1.0/deviceManagement/deviceCategories`` response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
