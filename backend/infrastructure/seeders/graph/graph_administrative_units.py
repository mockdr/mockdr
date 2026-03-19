"""Seed Microsoft Graph administrative units."""
from __future__ import annotations

from faker import Faker

from domain.graph.administrative_unit import GraphAdministrativeUnit
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.administrative_unit_repo import graph_admin_unit_repo


def seed_graph_administrative_units(fake: Faker, user_ids: list[str]) -> None:
    """Create two administrative units for the mock tenant."""
    units: list[GraphAdministrativeUnit] = [
        GraphAdministrativeUnit(
            id=graph_uuid(),
            displayName="Germany Office",
            description="Administrative unit for the Germany office",
            visibility="Public",
        ),
        GraphAdministrativeUnit(
            id=graph_uuid(),
            displayName="US Office",
            description="Administrative unit for the US office",
            visibility="Public",
        ),
    ]

    for unit in units:
        graph_admin_unit_repo.save(unit)
