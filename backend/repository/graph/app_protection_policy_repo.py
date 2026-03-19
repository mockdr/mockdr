"""Repository for Microsoft Graph App Protection Policy entities."""
from domain.graph.app_protection_policy import GraphAppProtectionPolicy
from repository.base import Repository


class GraphAppProtectionPolicyRepository(Repository[GraphAppProtectionPolicy]):
    """In-memory repository for ``GraphAppProtectionPolicy`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_app_protection_policies collection."""
        super().__init__("graph_app_protection_policies")


graph_app_protection_policy_repo = GraphAppProtectionPolicyRepository()
