"""Seed Microsoft Graph subscribed SKUs (licenses)."""
from __future__ import annotations

from faker import Faker

from domain.graph.subscribed_sku import GraphSubscribedSku
from infrastructure.seeders.graph.graph_shared import (
    SKU_ID_INTUNE_P1,
    SKU_ID_M365_BUSINESS_PREMIUM,
    SKU_ID_M365_E3,
    SKU_ID_M365_E5,
    SKU_ID_MDE_P2,
    graph_uuid,
)
from repository.graph.subscribed_sku_repo import graph_subscribed_sku_repo


def seed_graph_subscribed_skus(fake: Faker) -> None:
    """Create five subscribed SKU records representing common M365 licences."""
    skus: list[GraphSubscribedSku] = [
        GraphSubscribedSku(
            id=graph_uuid(),
            skuId=SKU_ID_M365_E5,
            skuPartNumber="SPE_E5",
            capabilityStatus="Enabled",
            consumedUnits=3,
            prepaidUnits={"enabled": 5, "suspended": 0, "warning": 0},
            servicePlans=[
                {"servicePlanId": graph_uuid(), "servicePlanName": "EXCHANGE_S_ENTERPRISE"},
                {"servicePlanId": graph_uuid(), "servicePlanName": "SHAREPOINTENTERPRISE"},
                {"servicePlanId": graph_uuid(), "servicePlanName": "MDE_ATP"},
            ],
            appliesTo="User",
        ),
        GraphSubscribedSku(
            id=graph_uuid(),
            skuId=SKU_ID_M365_E3,
            skuPartNumber="SPE_E3",
            capabilityStatus="Enabled",
            consumedUnits=8,
            prepaidUnits={"enabled": 10, "suspended": 0, "warning": 0},
            servicePlans=[
                {"servicePlanId": graph_uuid(), "servicePlanName": "EXCHANGE_S_ENTERPRISE"},
                {"servicePlanId": graph_uuid(), "servicePlanName": "SHAREPOINTENTERPRISE"},
            ],
            appliesTo="User",
        ),
        GraphSubscribedSku(
            id=graph_uuid(),
            skuId=SKU_ID_M365_BUSINESS_PREMIUM,
            skuPartNumber="SPB",
            capabilityStatus="Enabled",
            consumedUnits=20,
            prepaidUnits={"enabled": 25, "suspended": 0, "warning": 0},
            servicePlans=[
                {"servicePlanId": graph_uuid(), "servicePlanName": "EXCHANGE_S_STANDARD"},
                {"servicePlanId": graph_uuid(), "servicePlanName": "SHAREPOINTWAC"},
            ],
            appliesTo="User",
        ),
        GraphSubscribedSku(
            id=graph_uuid(),
            skuId=SKU_ID_MDE_P2,
            skuPartNumber="WIN_DEF_ATP",
            capabilityStatus="Enabled",
            consumedUnits=3,
            prepaidUnits={"enabled": 5, "suspended": 0, "warning": 0},
            servicePlans=[
                {"servicePlanId": graph_uuid(), "servicePlanName": "WINDEFATP"},
            ],
            appliesTo="User",
        ),
        GraphSubscribedSku(
            id=graph_uuid(),
            skuId=SKU_ID_INTUNE_P1,
            skuPartNumber="INTUNE_A",
            capabilityStatus="Enabled",
            consumedUnits=24,  # Near exhaustion — compliance warning
            prepaidUnits={"enabled": 25, "suspended": 0, "warning": 1},
            servicePlans=[
                {"servicePlanId": graph_uuid(), "servicePlanName": "INTUNE_A"},
            ],
            appliesTo="User",
        ),
    ]

    for sku in skus:
        graph_subscribed_sku_repo.save(sku)
