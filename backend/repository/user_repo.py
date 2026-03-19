from domain.user import User
from repository.base import Repository
from repository.store import store


class UserRepository(Repository[User]):
    """Repository for User entities with API token lookup support."""

    def __init__(self) -> None:
        """Initialise the repository bound to the users collection."""
        super().__init__("users")

    def get_by_token(self, token: str) -> User | None:
        """Return the user associated with the given API token, or None."""
        token_data = store.get("api_tokens", token)
        if not token_data:
            return None
        return self.get(token_data["userId"])

    def get_token_record(self, token: str) -> dict | None:
        """Return the raw token record dict for the given token, or None."""
        return store.get("api_tokens", token)

    def save_token(self, token: str, record: dict) -> None:
        """Persist an API token record keyed by the token string."""
        store.save("api_tokens", token, record)

    def list_tokens(self) -> list[dict]:
        """Return all API token records stored in the mock.

        Returns:
            List of raw token record dicts.
        """
        return list(store.get_all("api_tokens"))


user_repo = UserRepository()
