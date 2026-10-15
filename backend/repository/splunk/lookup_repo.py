"""Repositories for Splunk lookup definitions and CSV lookup files."""
from domain.splunk.lookup import LookupDefinition, LookupFile
from repository.base import Repository


class LookupDefinitionRepository(Repository[LookupDefinition]):
    """In-memory repository for ``transforms.conf`` lookup stanzas."""

    def __init__(self) -> None:
        """Bind to the splunk_lookup_definitions collection."""
        super().__init__("splunk_lookup_definitions")

    def find(self, name: str) -> LookupDefinition | None:
        """The definition a search's lookup name resolves to.

        Every definition mockdr holds is shared globally (``export =
        system``), as the ones Enterprise Security ships are, so a name is
        found whichever app it lives in. The search app wins a tie.
        """
        matches = [d for d in self.list_all() if d.name == name]
        matches.sort(key=lambda d: d.app != "search")
        return matches[0] if matches else None


class LookupFileRepository(Repository[LookupFile]):
    """In-memory repository for CSV lookup table files."""

    def __init__(self) -> None:
        """Bind to the splunk_lookup_files collection."""
        super().__init__("splunk_lookup_files")

    def find(self, name: str) -> LookupFile | None:
        """A CSV file by its file name, in whichever app holds it."""
        matches = [f for f in self.list_all() if f.name == name]
        matches.sort(key=lambda f: f.app != "search")
        return matches[0] if matches else None


lookup_definition_repo = LookupDefinitionRepository()
lookup_file_repo = LookupFileRepository()
