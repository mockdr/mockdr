"""Domain dataclass for a Splunk user."""
from dataclasses import dataclass, field


@dataclass
class SplunkUser:
    """A Splunk user account with roles and capabilities."""

    username: str
    password: str = ""
    realname: str = ""
    email: str = ""
    roles: list[str] = field(default_factory=list)
    default_app: str = "search"
    tz: str = "UTC"

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.username
