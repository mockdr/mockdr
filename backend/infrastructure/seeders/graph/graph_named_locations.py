"""Seed Microsoft Graph named locations for Conditional Access."""
from __future__ import annotations

from faker import Faker

from domain.graph.named_location import GraphNamedLocation
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.named_location_repo import graph_named_location_repo
from utils.dt import utc_now


def seed_graph_named_locations(fake: Faker) -> None:
    """Create three named locations (two IP-based, one country-based)."""
    now = utc_now()

    locations: list[GraphNamedLocation] = [
        GraphNamedLocation(
            id=graph_uuid(),
            displayName="Corporate Network",
            odata_type="#microsoft.graph.ipNamedLocation",
            ipRanges=[
                {"cidrAddress": "10.0.0.0/8"},
                {"cidrAddress": "172.16.0.0/12"},
            ],
            isTrusted=True,
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphNamedLocation(
            id=graph_uuid(),
            displayName="Blocked Countries",
            odata_type="#microsoft.graph.countryNamedLocation",
            countriesAndRegions=["RU", "CN", "KP", "IR"],
            isTrusted=False,
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphNamedLocation(
            id=graph_uuid(),
            displayName="Trusted IPs",
            odata_type="#microsoft.graph.ipNamedLocation",
            ipRanges=[
                {"cidrAddress": "203.0.113.0/24"},
            ],
            isTrusted=True,
            createdDateTime=now,
            modifiedDateTime=now,
        ),
    ]

    for loc in locations:
        graph_named_location_repo.save(loc)
