from domain.alert import Alert
from repository.base import Repository
from repository.store import store


class AlertRepository(Repository[Alert]):
    """Repository for Alert entities.

    Overrides save because Alert has no top-level id field;
    the primary key is alertInfo["alertId"].
    """

    def __init__(self) -> None:
        """Initialise the repository bound to the alerts collection."""
        super().__init__("alerts")

    def save(self, entity: Alert) -> None:
        """Persist an Alert keyed by alertInfo["alertId"]."""
        store.save(self._collection, entity.alertInfo["alertId"], entity)


alert_repo = AlertRepository()
