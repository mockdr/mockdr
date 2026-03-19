"""Domain dataclass for Microsoft Graph Compliance Policy entity."""
from dataclasses import dataclass, field


@dataclass
class GraphCompliancePolicy:
    """An Intune compliance policy from Microsoft Graph.

    Maps 1:1 to real Graph API
    ``/v1.0/deviceManagement/deviceCompliancePolicies`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    odata_type: str = ""  # output as @odata.type
    createdDateTime: str = ""  # noqa: N815
    lastModifiedDateTime: str = ""  # noqa: N815
    version: int = 1
    assignments: list[dict] = field(default_factory=list)
