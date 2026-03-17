"""CrowdStrike OAuth client seeder — pre-seeds mock API credentials."""
from __future__ import annotations

from domain.cs_oauth_client import CsOAuthClient
from infrastructure.seeders.cs_shared import CS_CID
from repository.cs_oauth_client_repo import cs_oauth_client_repo

_MOCK_CLIENTS: list[dict[str, str]] = [
    {
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
        "name": "AcmeCorp Admin Client",
        "role": "admin",
    },
    {
        "client_id": "cs-mock-viewer-client",
        "client_secret": "cs-mock-viewer-secret",
        "name": "AcmeCorp Viewer Client",
        "role": "viewer",
    },
    {
        "client_id": "cs-mock-analyst-client",
        "client_secret": "cs-mock-analyst-secret",
        "name": "AcmeCorp Analyst Client",
        "role": "analyst",
    },
]


def seed_cs_oauth_clients() -> None:
    """Pre-seed CrowdStrike OAuth2 client credentials.

    Creates three mock clients (admin, viewer, analyst) with deterministic
    IDs and secrets for testing. Also populates the raw ``cs_oauth_clients``
    store collection used by the token endpoint.
    """
    for client_def in _MOCK_CLIENTS:
        cs_oauth_client_repo.save(CsOAuthClient(
            client_id=client_def["client_id"],
            client_secret=client_def["client_secret"],
            name=client_def["name"],
            role=client_def["role"],
            member_cid=CS_CID,
        ))
