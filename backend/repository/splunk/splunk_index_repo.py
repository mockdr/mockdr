"""Repository for Splunk index entities."""
from domain.splunk.splunk_index import SplunkIndex
from repository.base import Repository


class SplunkIndexRepository(Repository[SplunkIndex]):
    """In-memory repository for ``SplunkIndex`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_indexes collection."""
        super().__init__("splunk_indexes")


splunk_index_repo = SplunkIndexRepository()
