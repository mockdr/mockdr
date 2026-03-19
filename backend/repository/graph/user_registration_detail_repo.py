"""Repository for Microsoft Graph User Registration Detail entities."""
from domain.graph.user_registration_detail import GraphUserRegistrationDetail
from repository.base import Repository


class GraphUserRegistrationDetailRepository(Repository[GraphUserRegistrationDetail]):
    """In-memory repository for ``GraphUserRegistrationDetail`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_user_registration_details collection."""
        super().__init__("graph_user_registration_details")


graph_user_registration_detail_repo = GraphUserRegistrationDetailRepository()
