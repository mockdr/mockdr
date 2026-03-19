"""Repository for Splunk HEC token entities."""
from domain.splunk.hec_token import HecToken
from repository.base import Repository


class HecTokenRepository(Repository[HecToken]):
    """In-memory repository for ``HecToken`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_hec_tokens collection."""
        super().__init__("splunk_hec_tokens")

    def get_by_name(self, name: str) -> HecToken | None:
        """Look up an HEC token by its display name."""
        for token in self.list_all():
            if token.name == name:
                return token
        return None


hec_token_repo = HecTokenRepository()
