"""Repository for Palo Alto Cortex XDR Alert entities."""
from domain.xdr_alert import XdrAlert
from repository.base import Repository


class XdrAlertRepository(Repository[XdrAlert]):
    """In-memory repository for ``XdrAlert`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the xdr_alerts collection."""
        super().__init__("xdr_alerts")

    def get_by_incident_id(self, incident_id: str) -> list[XdrAlert]:
        """Return all alerts linked to the given incident ID.

        Args:
            incident_id: The parent incident identifier.

        Returns:
            List of matching ``XdrAlert`` objects.
        """
        return [a for a in self.list_all() if a.incident_id == incident_id]


xdr_alert_repo = XdrAlertRepository()
