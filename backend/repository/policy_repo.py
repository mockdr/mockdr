from domain.policy import Policy
from repository.base import Repository


class PolicyRepository(Repository[Policy]):
    """Repository for Policy entities with site and group scoping helpers."""

    def __init__(self) -> None:
        """Initialise the repository bound to the policies collection."""
        super().__init__("policies")

    def get_for_tenant(self) -> Policy | None:
        """Return the account-wide policy every scope below it inherits.

        `GET /tenant/policy` and `GET /accounts/{id}/policy` answered
        `{"data": null}` — a 200 with nothing in it — because the lookup
        below took a site or a group and there was no record for neither.
        """
        return self.get("tenant")

    def save_for_tenant(self, policy: Policy) -> None:
        """Persist the account-wide policy."""
        from repository.store import store
        store.save("policies", "tenant", policy)

    def get_for_site(self, site_id: str) -> Policy | None:
        """Return the policy for the given site, or None if not found."""
        return self.get(f"site:{site_id}")

    def get_for_group(self, group_id: str) -> Policy | None:
        """Return the policy for the given group, or None if not found."""
        return self.get(f"group:{group_id}")

    def save_for_site(self, site_id: str, policy: Policy) -> None:
        """Persist a policy scoped to the given site."""
        from repository.store import store
        store.save("policies", f"site:{site_id}", policy)

    def save_for_group(self, group_id: str, policy: Policy) -> None:
        """Persist a policy scoped to the given group."""
        from repository.store import store
        store.save("policies", f"group:{group_id}", policy)


policy_repo = PolicyRepository()
