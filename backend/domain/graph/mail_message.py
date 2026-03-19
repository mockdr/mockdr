"""Domain dataclass for Microsoft Graph Mail Message entity."""
from dataclasses import dataclass, field


@dataclass
class GraphMailMessage:
    """A mail message in a user's mailbox.

    Maps to ``/v1.0/users/{id}/messages`` Graph API response fields.
    """

    id: str  # noqa: A003
    subject: str = ""
    bodyPreview: str = ""  # noqa: N815
    body: dict = field(default_factory=dict)  # {contentType: "html", content: "..."}
    sender: dict = field(default_factory=dict)  # {emailAddress: {name, address}}
    toRecipients: list[dict] = field(default_factory=list)  # noqa: N815
    receivedDateTime: str = ""  # noqa: N815
    isRead: bool = False  # noqa: N815
    importance: str = "normal"  # low, normal, high
    hasAttachments: bool = False  # noqa: N815
    categories: list[str] = field(default_factory=list)
    _user_id: str = ""  # internal
    _folder_id: str = ""  # internal
