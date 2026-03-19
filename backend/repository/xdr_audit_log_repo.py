"""Repository for Palo Alto Cortex XDR Audit Log entities."""
from domain.xdr_audit_log import XdrAuditLog
from repository.base import Repository


class XdrAuditLogRepository(Repository[XdrAuditLog]):
    """In-memory repository for ``XdrAuditLog`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_audit_logs collection."""
        super().__init__("xdr_audit_logs")


xdr_audit_log_repo = XdrAuditLogRepository()
