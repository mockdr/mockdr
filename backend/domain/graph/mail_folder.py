"""Domain dataclass for Microsoft Graph Mail Folder entity."""
from dataclasses import dataclass


@dataclass
class GraphMailFolder:
    """A mail folder in a user's mailbox.

    Maps to ``/v1.0/users/{id}/mailFolders`` Graph API response fields.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    parentFolderId: str | None = None  # noqa: N815
    childFolderCount: int = 0  # noqa: N815
    totalItemCount: int = 0  # noqa: N815
    unreadItemCount: int = 0  # noqa: N815
    _user_id: str = ""  # internal
