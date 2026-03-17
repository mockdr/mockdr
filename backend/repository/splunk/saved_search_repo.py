"""Repository for Splunk saved search entities."""
from domain.splunk.saved_search import SavedSearch
from repository.base import Repository


class SavedSearchRepository(Repository[SavedSearch]):
    """In-memory repository for ``SavedSearch`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_saved_searches collection."""
        super().__init__("splunk_saved_searches")


saved_search_repo = SavedSearchRepository()
