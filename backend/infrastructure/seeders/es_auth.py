"""Elastic Security API key seeder -- pre-seeds mock API keys."""
from __future__ import annotations

from repository.store import store

_MOCK_API_KEYS: list[dict[str, str]] = [
    {
        "id": "es-admin-key-001",
        "api_key": "mock-es-admin-api-key",
        "name": "AcmeCorp Admin API Key",
        "role": "admin",
    },
    {
        "id": "es-analyst-key-001",
        "api_key": "mock-es-analyst-api-key",
        "name": "AcmeCorp Analyst API Key",
        "role": "analyst",
    },
    {
        "id": "es-viewer-key-001",
        "api_key": "mock-es-viewer-api-key",
        "name": "AcmeCorp Viewer API Key",
        "role": "viewer",
    },
]


def seed_es_api_keys() -> None:
    """Pre-seed Elastic Security API keys.

    Creates three mock API keys (admin, analyst, viewer) with deterministic
    IDs and secrets for testing.
    """
    for key_def in _MOCK_API_KEYS:
        store.save("es_api_keys", key_def["id"], key_def)
