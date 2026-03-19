"""Domain dataclass for Microsoft Graph Directory Role entity."""
from dataclasses import dataclass


@dataclass
class GraphDirectoryRole:
    """An Azure AD / Entra ID directory role.

    Maps 1:1 to real Graph API ``/v1.0/directoryRoles`` response fields.
    """

    id: str  # noqa: A003 — role GUID
    displayName: str = ""  # noqa: N815
    description: str = ""
    roleTemplateId: str = ""  # noqa: N815
