"""Domain dataclass for Palo Alto Cortex XDR Audit Log entry."""
from dataclasses import dataclass


@dataclass
class XdrAuditLog:
    """A Cortex XDR management audit log entry."""

    audit_id: str
    sub_type: str = ""
    result: str = "SUCCESS"
    timestamp: int = 0  # epoch ms
    user_name: str = ""
    user_email: str = ""
    description: str = ""
    host_name: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.audit_id
