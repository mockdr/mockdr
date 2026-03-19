"""Repository for Microsoft Graph Mail Rule entities."""
from domain.graph.mail_rule import GraphMailRule
from repository.base import Repository
from repository.store import store


class GraphMailRuleRepository(Repository[GraphMailRule]):
    """In-memory repository for ``GraphMailRule`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the graph_mail_rules collection."""
        super().__init__("graph_mail_rules")

    def save(self, entity: GraphMailRule) -> None:
        """Persist a mail rule, keyed by ``{user_id}:{rule_id}``."""
        store.save(self._collection, f"{entity._user_id}:{entity.id}", entity)


graph_mail_rule_repo = GraphMailRuleRepository()
