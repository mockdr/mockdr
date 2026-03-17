from repository.base import Repository


class BlocklistRepository(Repository[dict]):
    """Repository for blocklist (hash restriction) entries stored as raw dicts."""

    def __init__(self) -> None:
        """Initialise the repository bound to the blocklist collection."""
        super().__init__("blocklist")


blocklist_repo = BlocklistRepository()
