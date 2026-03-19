"""Domain dataclass for CrowdStrike Falcon User entities."""
from dataclasses import dataclass, field


@dataclass
class CsUser:
    """A CrowdStrike Falcon user account.

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    """

    uuid: str
    cid: str
    uid: str  # email address
    first_name: str = ""
    last_name: str = ""
    customer: str = ""
    roles: list[str] = field(default_factory=list)
    created_at: str = ""
    last_login_at: str = ""
    status: str = "active"

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.uuid
