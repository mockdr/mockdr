"""Repository for scoped tag definitions."""
from domain.tag import Tag
from repository.base import Repository


class TagRepository(Repository[Tag]):
    """In-memory repository for ``Tag`` domain objects."""

    def __init__(self) -> None:
        """Initialize the tag repository."""
        super().__init__("tags")


tag_repo = TagRepository()
