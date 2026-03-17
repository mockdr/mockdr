"""Repository for Splunk ES notable event entities."""
from domain.splunk.notable_event import NotableEvent
from repository.base import Repository


class NotableEventRepository(Repository[NotableEvent]):
    """In-memory repository for ``NotableEvent`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_notables collection."""
        super().__init__("splunk_notables")

    def list_by_status(self, status: str) -> list[NotableEvent]:
        """Return notables filtered by status code."""
        return [n for n in self.list_all() if n.status == status]


notable_event_repo = NotableEventRepository()
