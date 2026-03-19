"""Repository for Microsoft Defender for Endpoint Indicator entities."""
from domain.mde_indicator import MdeIndicator
from repository.base import Repository


class MdeIndicatorRepository(Repository[MdeIndicator]):
    """In-memory repository for ``MdeIndicator`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the mde_indicators collection."""
        super().__init__("mde_indicators")


mde_indicator_repo = MdeIndicatorRepository()
