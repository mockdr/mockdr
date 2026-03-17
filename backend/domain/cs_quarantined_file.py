"""Domain dataclass for CrowdStrike Falcon Quarantined File entities."""
from dataclasses import dataclass, field


@dataclass
class CsQuarantinedFile:
    """A CrowdStrike Falcon quarantined file.

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    """

    id: str
    cid: str
    aid: str  # device_id of the host
    sha256: str
    filename: str
    paths: str = ""
    state: str = "quarantined"  # quarantined, released, deleted
    hostname: str = ""
    username: str = ""
    date_updated: str = ""
    date_created: str = ""
    detect_ids: list[str] = field(default_factory=list)
