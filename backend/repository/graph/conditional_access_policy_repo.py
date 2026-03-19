"""Repository for Microsoft Graph Conditional Access Policy entities."""
from domain.graph.conditional_access_policy import GraphConditionalAccessPolicy
from repository.base import Repository


class GraphConditionalAccessPolicyRepository(Repository[GraphConditionalAccessPolicy]):
    """In-memory repository for ``GraphConditionalAccessPolicy`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_conditional_access_policies collection."""
        super().__init__("graph_conditional_access_policies")


graph_ca_policy_repo = GraphConditionalAccessPolicyRepository()
