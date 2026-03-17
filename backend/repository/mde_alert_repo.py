"""Repository for Microsoft Defender for Endpoint Alert entities."""
from domain.mde_alert import MdeAlert
from repository.base import Repository


class MdeAlertRepository(Repository[MdeAlert]):
    """In-memory repository for ``MdeAlert`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_alerts collection."""
        super().__init__("mde_alerts")

    def get_by_machine_id(self, machine_id: str) -> list[MdeAlert]:
        """Return all alerts associated with the given machine ID."""
        return [a for a in self.list_all() if a.machineId == machine_id]


mde_alert_repo = MdeAlertRepository()
