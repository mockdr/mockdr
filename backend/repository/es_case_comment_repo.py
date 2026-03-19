"""Repository for Elastic Security case comment entities."""
from __future__ import annotations

from domain.es_case_comment import EsCaseComment
from repository.base import Repository


class EsCaseCommentRepository(Repository[EsCaseComment]):
    """In-memory repository for ``EsCaseComment`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_case_comments collection."""
        super().__init__("es_case_comments")

    def get_by_case_id(self, case_id: str) -> list[EsCaseComment]:
        """Return all comments belonging to the given case."""
        return [c for c in self.list_all() if c.case_id == case_id]


es_case_comment_repo = EsCaseCommentRepository()
