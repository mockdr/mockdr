"""Repository for Splunk search job entities."""
from domain.splunk.search_job import SearchJob
from repository.base import Repository


class SearchJobRepository(Repository[SearchJob]):
    """In-memory repository for ``SearchJob`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_search_jobs collection."""
        super().__init__("splunk_search_jobs")


search_job_repo = SearchJobRepository()
