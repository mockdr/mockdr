"""Seed the Graph Organization entity."""
from __future__ import annotations

from faker import Faker

from domain.graph.organization import GraphOrganization
from infrastructure.seeders.graph.graph_shared import (
    GRAPH_COMPANY_NAME,
    GRAPH_DOMAIN,
    GRAPH_TENANT_ID,
)
from repository.graph.organization_repo import graph_organization_repo


def seed_graph_organization(fake: Faker) -> None:
    """Create the single Organization record for the mock tenant."""
    org = GraphOrganization(
        id=GRAPH_TENANT_ID,
        displayName=GRAPH_COMPANY_NAME,
        verifiedDomains=[
            {
                "capabilities": "Email, OfficeCommunicationsOnline",
                "isDefault": True,
                "isInitial": True,
                "name": GRAPH_DOMAIN,
                "type": "Managed",
            },
        ],
        assignedPlans=[
            {
                "assignedDateTime": "2024-01-15T00:00:00Z",
                "capabilityStatus": "Enabled",
                "service": "MicrosoftDefenderATP",
                "servicePlanId": "8e0c0a52-d3b7-4ee4-9091-1c0b1c120b50",
            },
            {
                "assignedDateTime": "2024-01-15T00:00:00Z",
                "capabilityStatus": "Enabled",
                "service": "exchange",
                "servicePlanId": "efb87545-963c-4e0d-99df-69c6916d9eb0",
            },
            {
                "assignedDateTime": "2024-01-15T00:00:00Z",
                "capabilityStatus": "Enabled",
                "service": "MicrosoftOffice",
                "servicePlanId": "43de0ff5-c92c-492b-9116-175376d08c38",
            },
        ],
        tenantType="AAD",
        createdDateTime="2023-06-01T08:00:00Z",
        city="San Francisco",
        country="US",
        postalCode="94105",
        state="CA",
        street="123 Market Street",
    )
    graph_organization_repo.save(org)
