from domain.account import Account
from repository.base import Repository


class AccountRepository(Repository[Account]):
    """Repository for Account entities."""

    def __init__(self) -> None:
        """Initialise the repository bound to the accounts collection."""
        super().__init__("accounts")


account_repo = AccountRepository()
