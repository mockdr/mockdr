"""Domain dataclass for Microsoft Graph Drive Item entity."""
from dataclasses import dataclass, field


@dataclass
class GraphDriveItem:
    """A file or folder in a drive.

    Maps to ``/v1.0/drives/{id}/items`` Graph API response fields.
    """

    id: str  # noqa: A003
    name: str = ""
    size: int = 0
    createdDateTime: str = ""  # noqa: N815
    lastModifiedDateTime: str = ""  # noqa: N815
    webUrl: str = ""  # noqa: N815
    file: dict | None = None  # {mimeType: "..."} — present for files
    folder: dict | None = None  # {childCount: N} — present for folders
    parentReference: dict = field(default_factory=dict)  # noqa: N815 — {driveId, id, path}
    createdBy: dict = field(default_factory=dict)  # noqa: N815
    lastModifiedBy: dict = field(default_factory=dict)  # noqa: N815
    _drive_id: str = ""  # internal
