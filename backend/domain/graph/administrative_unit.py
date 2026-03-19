"""Domain dataclass for Microsoft Graph Administrative Unit entity."""
from dataclasses import dataclass


@dataclass
class GraphAdministrativeUnit:
    """An Entra ID administrative unit.

    Maps 1:1 to real Graph API ``/v1.0/directory/administrativeUnits``
    response fields.  Field names use camelCase to match the Graph API JSON format.
    """

    id: str  # noqa: A003
    displayName: str = ""  # noqa: N815
    description: str = ""
    visibility: str = ""
