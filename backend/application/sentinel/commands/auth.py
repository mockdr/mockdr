"""Sentinel OAuth2 authentication command handlers."""
from __future__ import annotations

import hmac

from api.sentinel_auth import create_sentinel_token
from repository.store import store

_OAUTH_CLIENTS_COLLECTION = "sentinel_oauth_clients"


def token_exchange(client_id: str, client_secret: str) -> dict | None:
    """Exchange client credentials for an access token.

    Args:
        client_id:     Azure AD application client ID.
        client_secret: Client secret.

    Returns:
        Token response dict, or None if credentials are invalid.
    """
    clients = store.get_all(_OAUTH_CLIENTS_COLLECTION)
    for c in clients:
        stored_id = c.get("client_id", "")
        stored_secret = c.get("client_secret", "")
        id_ok = hmac.compare_digest(stored_id, client_id)
        secret_ok = hmac.compare_digest(stored_secret, client_secret)
        if id_ok and secret_ok:
            return create_sentinel_token(client_id)
    return None
