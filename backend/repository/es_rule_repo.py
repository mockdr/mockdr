"""Repository for Elastic Security detection rule entities."""
from __future__ import annotations

from domain.es_rule import EsRule
from repository.base import Repository


class EsRuleRepository(Repository[EsRule]):
    """In-memory repository for ``EsRule`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the es_rules collection."""
        super().__init__("es_rules")

    def get_by_rule_id(self, rule_id: str) -> EsRule | None:
        """Return the first rule matching the given rule_id, or None."""
        for rule in self.list_all():
            if rule.rule_id == rule_id:
                return rule
        return None



es_rule_repo = EsRuleRepository()
