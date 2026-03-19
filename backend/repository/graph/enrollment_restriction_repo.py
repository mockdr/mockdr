"""Repository for Microsoft Graph Enrollment Restriction entities."""
from domain.graph.enrollment_restriction import GraphEnrollmentRestriction
from repository.base import Repository


class GraphEnrollmentRestrictionRepository(Repository[GraphEnrollmentRestriction]):
    """In-memory repository for ``GraphEnrollmentRestriction`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_enrollment_restrictions collection."""
        super().__init__("graph_enrollment_restrictions")


graph_enrollment_restriction_repo = GraphEnrollmentRestrictionRepository()
