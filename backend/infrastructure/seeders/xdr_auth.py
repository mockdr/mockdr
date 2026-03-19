"""XDR API key seeder -- pre-seeds mock HMAC API credentials."""
from __future__ import annotations

from domain.xdr_api_key import XdrApiKey
from repository.xdr_api_key_repo import xdr_api_key_repo

_MOCK_KEYS: list[dict[str, str]] = [
    {
        "key_id": "1",
        "key_secret": "xdr-admin-secret",
        "name": "AcmeCorp XDR Admin Key",
        "role": "admin",
    },
    {
        "key_id": "2",
        "key_secret": "xdr-analyst-secret",
        "name": "AcmeCorp XDR Analyst Key",
        "role": "analyst",
    },
    {
        "key_id": "3",
        "key_secret": "xdr-viewer-secret",
        "name": "AcmeCorp XDR Viewer Key",
        "role": "viewer",
    },
]


def seed_xdr_api_keys() -> None:
    """Pre-seed Cortex XDR API key credentials.

    Creates three mock API keys (admin, analyst, viewer) with deterministic
    IDs and secrets for testing.
    """
    for key_def in _MOCK_KEYS:
        xdr_api_key_repo.save(XdrApiKey(
            key_id=key_def["key_id"],
            key_secret=key_def["key_secret"],
            name=key_def["name"],
            role=key_def["role"],
        ))
