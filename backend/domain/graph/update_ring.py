"""Domain dataclass for Microsoft Graph Windows Update Ring entity."""
from dataclasses import dataclass


@dataclass
class GraphUpdateRing:
    """A Windows Update for Business configuration (update ring) from Microsoft Graph.

    Maps to real Graph API
    ``/beta/deviceManagement/windowsUpdateForBusinessConfigurations`` response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    qualityUpdatesDeferralPeriodInDays: int = 0  # noqa: N815
    featureUpdatesDeferralPeriodInDays: int = 0  # noqa: N815
    autoInstallAtMaintenanceTime: bool = True  # noqa: N815
    deliveryOptimizationMode: str = "httpOnly"  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
