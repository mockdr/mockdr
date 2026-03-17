"""Repository for Splunk event entities."""
from domain.splunk.splunk_event import SplunkEvent
from repository.base import Repository


class SplunkEventRepository(Repository[SplunkEvent]):
    """In-memory repository for ``SplunkEvent`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_events collection."""
        super().__init__("splunk_events")

    def list_by_index(self, index: str) -> list[SplunkEvent]:
        """Return all events in the given index.

        Args:
            index: The Splunk index name to filter by.

        Returns:
            List of matching events sorted by time descending.
        """
        events = [e for e in self.list_all() if e.index == index]
        events.sort(key=lambda e: e.time, reverse=True)
        return events

    def list_by_index_and_sourcetype(
        self, index: str, sourcetype: str,
    ) -> list[SplunkEvent]:
        """Return events matching both index and sourcetype.

        Args:
            index: The Splunk index name.
            sourcetype: The sourcetype to filter by.

        Returns:
            List of matching events sorted by time descending.
        """
        events = [
            e for e in self.list_all()
            if e.index == index and e.sourcetype == sourcetype
        ]
        events.sort(key=lambda e: e.time, reverse=True)
        return events

    def count_by_index(self, index: str) -> int:
        """Return the number of events in the given index."""
        return sum(1 for e in self.list_all() if e.index == index)


splunk_event_repo = SplunkEventRepository()
