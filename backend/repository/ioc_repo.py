from domain.ioc import IOC
from repository.base import Repository
from repository.store import store


class IOCRepository(Repository[IOC]):
    """Repository for IOC (Indicator of Compromise) entities.

    Overrides save because the IOC primary key is uuid, not id.
    """

    def __init__(self) -> None:
        """Initialise the repository bound to the iocs collection."""
        super().__init__("iocs")

    def save(self, entity: IOC) -> None:
        """Persist an IOC keyed by its uuid."""
        store.save(self._collection, entity.uuid, entity)


ioc_repo = IOCRepository()
