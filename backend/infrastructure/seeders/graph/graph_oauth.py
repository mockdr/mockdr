"""Seed pre-registered Graph API OAuth2 clients.

Each client is associated with a plan level and license set that drives
feature gating across Graph endpoints.
"""
from __future__ import annotations

from domain.graph.oauth_client import GraphOAuthClient
from infrastructure.seeders.graph.graph_shared import GRAPH_TENANT_ID
from repository.graph.oauth_client_repo import graph_oauth_client_repo

_MOCK_CLIENTS: list[dict] = [
    {
        "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "name": "AcmeCorp Global Admin",
        "plan": "plan2",
        "licenses": ["E5", "Intune"],
        "role": "owner",
    },
    {
        "client_id": "graph-mock-security-client",
        "client_secret": "graph-mock-security-secret",
        "name": "AcmeCorp Security Admin",
        "plan": "plan2",
        "licenses": ["E5"],
        "role": "contributor",
    },
    {
        "client_id": "graph-mock-smb-client",
        "client_secret": "graph-mock-smb-secret",
        "name": "AcmeCorp SMB Admin",
        "plan": "defender_for_business",
        "licenses": ["Business Premium"],
        "role": "contributor",
    },
    {
        "client_id": "graph-mock-p1-client",
        "client_secret": "graph-mock-p1-secret",
        "name": "AcmeCorp Plan 1 User",
        "plan": "plan1",
        "licenses": ["E3"],
        "role": "reader",
    },
    {
        "client_id": "graph-mock-intune-client",
        "client_secret": "graph-mock-intune-secret",
        "name": "AcmeCorp Intune Admin",
        "plan": "plan2",
        "licenses": ["E3", "Intune"],
        "role": "contributor",
    },
    {
        "client_id": "graph-mock-mail-client",
        "client_secret": "graph-mock-mail-secret",
        "name": "AcmeCorp Mail Only",
        "plan": "none",
        "licenses": ["E3"],
        "role": "reader",
    },
]


def seed_graph_oauth_clients() -> None:
    """Populate the Graph OAuth2 client store with pre-defined test clients."""
    for spec in _MOCK_CLIENTS:
        client = GraphOAuthClient(
            client_id=spec["client_id"],
            client_secret=spec["client_secret"],
            tenant_id=GRAPH_TENANT_ID,
            name=spec["name"],
            plan=spec["plan"],
            licenses=spec["licenses"],
            role=spec["role"],
        )
        graph_oauth_client_repo.save(client)
