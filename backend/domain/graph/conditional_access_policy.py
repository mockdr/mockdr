"""Domain dataclass for Microsoft Graph Conditional Access Policy entity."""
from dataclasses import dataclass, field


@dataclass
class GraphConditionalAccessPolicy:
    """A Conditional Access policy from Entra ID.

    Maps 1:1 to real Graph API ``/v1.0/identity/conditionalAccess/policies``
    response fields.  Field names use camelCase to match the Graph API JSON
    format.
    """
    id: str  # noqa: A003 — GUID
    displayName: str = ""  # noqa: N815
    state: str = "enabled"  # enabled | disabled | enabledForReportingButNotEnforced
    conditions: dict = field(default_factory=dict)
    grantControls: dict = field(default_factory=dict)  # noqa: N815
    sessionControls: dict | None = None  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    modifiedDateTime: str = ""  # noqa: N815
