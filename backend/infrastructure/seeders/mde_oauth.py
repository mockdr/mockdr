"""MDE OAuth client seeder -- pre-seeds mock API credentials."""
from __future__ import annotations

from domain.mde_oauth_client import MdeOAuthClient
from infrastructure.seeders.mde_shared import MDE_TENANT_ID
from repository.mde_oauth_client_repo import mde_oauth_client_repo

_MOCK_CLIENTS: list[dict[str, str]] = [
    {
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "name": "AcmeCorp MDE Admin Client",
        "role": "admin",
    },
    {
        "client_id": "mde-mock-analyst-client",
        "client_secret": "mde-mock-analyst-secret",
        "name": "AcmeCorp MDE Analyst Client",
        "role": "analyst",
    },
    {
        "client_id": "mde-mock-viewer-client",
        "client_secret": "mde-mock-viewer-secret",
        "name": "AcmeCorp MDE Viewer Client",
        "role": "viewer",
    },
]


def seed_mde_oauth_clients() -> None:
    """Pre-seed MDE OAuth2 client credentials.

    Creates three mock clients (admin, analyst, viewer) with deterministic
    IDs and secrets for testing.
    """
    for client_def in _MOCK_CLIENTS:
        mde_oauth_client_repo.save(MdeOAuthClient(
            client_id=client_def["client_id"],
            client_secret=client_def["client_secret"],
            tenant_id=MDE_TENANT_ID,
            name=client_def["name"],
            role=client_def["role"],
        ))
