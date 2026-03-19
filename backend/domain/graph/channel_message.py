"""Domain dataclass for Microsoft Graph Channel Message entity."""
from dataclasses import dataclass, field


@dataclass
class GraphChannelMessage:
    """A message in a Teams channel.

    Maps to ``/v1.0/teams/{id}/channels/{id}/messages`` Graph API response fields.
    The ``_from`` field is output as ``from`` in API responses.
    """

    id: str  # noqa: A003
    body: dict = field(default_factory=dict)  # {content, contentType}
    createdDateTime: str = ""  # noqa: N815
    importance: str = "normal"
    _from: dict = field(default_factory=dict)  # {user: {id, displayName}} — output as "from"
    _team_id: str = ""  # internal
    _channel_id: str = ""  # internal
