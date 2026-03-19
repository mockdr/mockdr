"""Domain dataclass for Microsoft Graph Channel entity."""
from dataclasses import dataclass


@dataclass
class GraphChannel:
    """A channel within a Microsoft Teams team.

    Maps to ``/v1.0/teams/{id}/channels`` Graph API response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    membershipType: str = "standard"  # noqa: N815 — standard, private, shared
    _team_id: str = ""  # internal
