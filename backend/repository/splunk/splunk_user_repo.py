"""Repository for Splunk user entities."""
import hmac

from domain.splunk.splunk_user import SplunkUser
from repository.base import Repository


class SplunkUserRepository(Repository[SplunkUser]):
    """In-memory repository for ``SplunkUser`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the splunk_users collection."""
        super().__init__("splunk_users")

    def authenticate(self, username: str, password: str) -> SplunkUser | None:
        """Validate credentials and return the user if valid."""
        user = self.get(username)
        if user and hmac.compare_digest(user.password, password):
            return user
        return None


splunk_user_repo = SplunkUserRepository()
