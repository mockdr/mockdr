"""Domain dataclass for Microsoft Graph Drive entity."""
from dataclasses import dataclass, field


@dataclass
class GraphDrive:
    """A user's OneDrive or SharePoint document library.

    Maps to ``/v1.0/users/{id}/drive`` Graph API response fields.
    """

    id: str  # noqa: A003
    name: str = ""
    driveType: str = "personal"  # noqa: N815 — personal, business, documentLibrary
    owner: dict = field(default_factory=dict)  # {user: {id, displayName}}
    quota: dict = field(default_factory=dict)  # {total, used, remaining}
    webUrl: str = ""  # noqa: N815
    _user_id: str = ""  # internal
