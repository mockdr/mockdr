"""Domain dataclass for Microsoft Graph Named Location entity."""
from dataclasses import dataclass, field


@dataclass
class GraphNamedLocation:
    """An Entra ID named location (IP or country-based).

    Maps 1:1 to real Graph API ``/v1.0/identity/conditionalAccess/namedLocations``
    response fields.  Field names use camelCase to match the Graph API JSON format.

    Note: ``odata_type`` is stored internally and serialised as ``@odata.type``
    in API responses.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    odata_type: str = ""  # stored as "@odata.type" in output
    ipRanges: list[dict] = field(default_factory=list)  # noqa: N815 — for IP locations
    countriesAndRegions: list[str] = field(default_factory=list)  # noqa: N815 — for country locations
    isTrusted: bool = False  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
    modifiedDateTime: str = ""  # noqa: N815
