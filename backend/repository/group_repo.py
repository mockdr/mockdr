from domain.group import Group
from repository.base import Repository


class GroupRepository(Repository[Group]):
    """Repository for Group entities with site-scoped lookup."""

    def __init__(self) -> None:
        """Initialise the repository bound to the groups collection."""
        super().__init__("groups")

    def get_by_site(self, site_id: str) -> list[Group]:
        """Return all groups belonging to the given site."""
        return [g for g in self.list_all() if g.siteId == site_id]


group_repo = GroupRepository()
