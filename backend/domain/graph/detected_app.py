"""Domain dataclass for Microsoft Graph Detected App entity (Intune)."""
from dataclasses import dataclass


@dataclass
class GraphDetectedApp:
    """An application detected on Intune-managed devices.

    Maps 1:1 to real Graph API
    ``/v1.0/deviceManagement/detectedApps`` response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    version: str = ""
    deviceCount: int = 0  # noqa: N815
    sizeInByte: int = 0  # noqa: N815
    platform: str = "unknown"  # windows | macOS | linux
    publisher: str = ""
