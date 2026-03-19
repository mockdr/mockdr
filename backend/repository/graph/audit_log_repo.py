"""Repository for Microsoft Graph Directory Audit Log entities."""
from domain.graph.audit_log import GraphAuditLog
from repository.base import Repository


class GraphAuditLogRepository(Repository[GraphAuditLog]):
    """In-memory repository for ``GraphAuditLog`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_audit_logs collection."""
        super().__init__("graph_audit_logs")


graph_audit_log_repo = GraphAuditLogRepository()
