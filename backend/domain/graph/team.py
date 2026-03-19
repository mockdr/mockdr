"""Domain dataclass for Microsoft Graph Team entity."""
from dataclasses import dataclass, field


@dataclass
class GraphTeam:
    """A Microsoft Teams team.

    Maps to ``/v1.0/teams`` Graph API response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    createdDateTime: str = ""  # noqa: N815
    visibility: str = "public"  # public, private
    memberSettings: dict = field(default_factory=dict)  # noqa: N815
    messagingSettings: dict = field(default_factory=dict)  # noqa: N815
