"""Sentinel OAuth2 authentication command handlers."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

from api.sentinel_auth import create_sentinel_token
from repository.store import store

_OAUTH_CLIENTS_COLLECTION = "sentinel_oauth_clients"


@dataclass(frozen=True)
class SentinelClient:
    """A registered application, as the Entra authority reads one."""

    client_id: str
    client_secret: str
    tenant_id: str
    tenant_domain: str


def _client(record: dict) -> SentinelClient:
    return SentinelClient(
        client_id=record.get("client_id", ""),
        client_secret=record.get("client_secret", ""),
        tenant_id=record.get("tenant_id", ""),
        tenant_domain=record.get("tenant_domain", ""),
    )


def registered_clients() -> list[SentinelClient]:
    """Every application registered in this directory."""
    return [_client(c) for c in store.get_all(_OAUTH_CLIENTS_COLLECTION)]


def find_client(client_id: str) -> SentinelClient | None:
    """The registered application with *client_id*, or None.

    Every registration is compared, in constant time, so the answer takes
    as long for an ID that is registered as for one that is not.
    """
    found = None
    for client in registered_clients():
        if hmac.compare_digest(client.client_id, client_id):
            found = client
    return found


def mint_token(client: Any, client_id: str, scope: str) -> dict:  # noqa: ANN401 - registered client
    """Issue a token for the resource *scope* names; see :func:`create_sentinel_token`."""
    return create_sentinel_token(client_id, scope, client.tenant_id)
