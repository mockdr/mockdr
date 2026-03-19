"""Domain dataclass for Microsoft Graph Autopilot Deployment Profile."""
from dataclasses import dataclass, field


@dataclass
class GraphAutopilotProfile:
    """A Windows Autopilot deployment profile from Microsoft Graph.

    Maps 1:1 to real Graph API
    ``/beta/deviceManagement/windowsAutopilotDeploymentProfiles`` response
    fields.  Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    outOfBoxExperienceSettings: dict = field(default_factory=dict)  # noqa: N815
    enrollmentStatusScreenSettings: dict = field(default_factory=dict)  # noqa: N815
