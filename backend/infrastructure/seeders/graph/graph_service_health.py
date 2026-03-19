"""Seed Microsoft Graph Service Health data."""
from __future__ import annotations

from faker import Faker

from domain.graph.service_health import GraphServiceHealth
from repository.graph.service_health_repo import graph_service_health_repo

_SERVICES: list[dict] = [
    {"id": "MicrosoftDefender", "service": "Microsoft Defender", "status": "serviceOperational"},
    {"id": "MicrosoftIntune", "service": "Microsoft Intune", "status": "serviceOperational"},
    {"id": "ExchangeOnline", "service": "Exchange Online", "status": "serviceOperational"},
    {"id": "SharePointOnline", "service": "SharePoint Online", "status": "serviceDegradation"},
    {"id": "MicrosoftTeams", "service": "Microsoft Teams", "status": "serviceOperational"},
    {"id": "AzureActiveDirectory", "service": "Azure Active Directory", "status": "serviceOperational"},
]


def seed_graph_service_health(fake: Faker) -> None:
    """Seed service health overview entries.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    for svc in _SERVICES:
        entry = GraphServiceHealth(
            id=svc["id"],
            service=svc["service"],
            status=svc["status"],
            isActive=True,
        )
        graph_service_health_repo.save(entry)
