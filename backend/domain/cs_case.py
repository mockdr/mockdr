"""Domain dataclass for CrowdStrike Falcon Case (Messaging Center) entities."""
from dataclasses import dataclass, field


@dataclass
class CsCase:
    """A CrowdStrike Falcon support case.

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    """

    id: str
    cid: str
    title: str
    body: str = ""
    detections: list[dict] = field(default_factory=list)
    incidents: list[dict] = field(default_factory=list)
    type: str = "standard"
    status: str = "open"  # open, closed, reopened
    ip_addresses: str = ""
    hosts: str = ""
    assigner: dict = field(default_factory=dict)
    assignee: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    fine_score: int = 0
    created_time: str = ""
    last_modified_time: str = ""
