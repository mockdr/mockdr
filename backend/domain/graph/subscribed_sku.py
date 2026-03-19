"""Domain dataclass for Microsoft Graph Subscribed SKU (license) entity."""
from dataclasses import dataclass, field


@dataclass
class GraphSubscribedSku:
    """An Entra ID subscribed SKU (license assignment).

    Maps 1:1 to real Graph API ``/v1.0/subscribedSkus`` response fields.
    Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    skuId: str = ""  # noqa: N815
    skuPartNumber: str = ""  # noqa: N815
    capabilityStatus: str = "Enabled"  # noqa: N815
    consumedUnits: int = 0  # noqa: N815
    prepaidUnits: dict = field(default_factory=dict)  # noqa: N815 — {enabled: int, suspended: int, warning: int}
    servicePlans: list[dict] = field(default_factory=list)  # noqa: N815
    appliesTo: str = "User"  # noqa: N815
