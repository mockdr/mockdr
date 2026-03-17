"""Domain dataclass for CrowdStrike Falcon Host Group entities."""
from dataclasses import dataclass


@dataclass
class CsHostGroup:
    """A CrowdStrike Falcon host group.

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    """

    id: str
    name: str = ""
    description: str = ""
    group_type: str = "static"
    assignment_rule: str = ""
    created_by: str = ""
    created_timestamp: str = ""
    modified_by: str = ""
    modified_timestamp: str = ""
