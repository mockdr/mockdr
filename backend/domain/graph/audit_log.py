"""Domain dataclass for Microsoft Graph Directory Audit Log entity."""
from dataclasses import dataclass, field


@dataclass
class GraphAuditLog:
    """An Entra ID directory audit log entry.

    Maps 1:1 to real Graph API ``/v1.0/auditLogs/directoryAudits`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """
    id: str  # noqa: A003
    category: str = ""
    correlationId: str = ""  # noqa: N815
    result: str = "success"  # success, failure
    activityDisplayName: str = ""  # noqa: N815
    activityDateTime: str = ""  # noqa: N815
    initiatedBy: dict = field(default_factory=dict)  # noqa: N815 — {user: {id, displayName, userPrincipalName}, app: {}}
    targetResources: list[dict] = field(default_factory=list)  # noqa: N815
    loggedByService: str = ""  # noqa: N815
