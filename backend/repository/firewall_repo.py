from domain.firewall_rule import FirewallRule
from repository.base import Repository


class FirewallRepository(Repository[FirewallRule]):
    """Repository for FirewallRule entities."""

    def __init__(self) -> None:
        """Initialise the repository bound to the firewall_rules collection."""
        super().__init__("firewall_rules")


firewall_repo = FirewallRepository()
