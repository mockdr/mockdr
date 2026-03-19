"""Domain dataclass for Microsoft Graph Mail Rule entity."""
from dataclasses import dataclass, field


@dataclass
class GraphMailRule:
    """A mail inbox rule.

    Maps 1:1 to real Graph API ``/v1.0/users/{id}/mailFolders/inbox/messageRules``
    response fields.  Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003 — GUID
    displayName: str = ""  # noqa: N815
    sequence: int = 1
    isEnabled: bool = True  # noqa: N815
    conditions: dict = field(default_factory=dict)  # noqa: N815 — {sentFrom, hasAttachments, subjectContains}
    actions: dict = field(default_factory=dict)  # noqa: N815 — {forwardTo, redirectTo, forwardAsAttachmentTo, delete, moveToFolder, stopProcessingRules}
    _user_id: str = ""  # internal — not serialised to API
