"""Domain dataclass for Microsoft Graph SharePoint Site entity."""
from dataclasses import dataclass


@dataclass
class GraphSharePointSite:
    """A SharePoint site.

    Maps to ``/v1.0/sites`` Graph API response fields.
    """

    id: str  # noqa: A003
    name: str = ""
    displayName: str = ""  # noqa: N815
    webUrl: str = ""  # noqa: N815
    createdDateTime: str = ""  # noqa: N815
