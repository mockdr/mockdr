"""Microsoft Graph OAuth2 token endpoint.

Implements the Azure AD client credentials flow: clients POST ``client_id``,
``client_secret``, and ``grant_type=client_credentials`` as form-encoded data
and receive a time-limited Bearer token.

Pre-seeded mock credentials (seeded via ``infrastructure/seeders/graph/graph_oauth.py``):

* Admin:    ``graph-mock-admin-client`` / ``graph-mock-admin-secret``
* Security: ``graph-mock-security-client`` / ``graph-mock-security-secret``
* SMB:      ``graph-mock-smb-client`` / ``graph-mock-smb-secret``
* Plan 1:   ``graph-mock-p1-client`` / ``graph-mock-p1-secret``
* Intune:   ``graph-mock-intune-client`` / ``graph-mock-intune-secret``
* Mail:     ``graph-mock-mail-client`` / ``graph-mock-mail-secret``
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from api.entra_authority import EntraDirectory, entra_authority_router
from repository.graph.oauth_client_repo import graph_oauth_client_repo
from repository.store import store
from utils.entra_access_token import mint_access_token, requested_resource
from utils.entra_app_roles import graph_roles
from utils.entra_client_auth import GRAPH_RESOURCES, require_default_scope

_TOKEN_LIFETIME_SECONDS: int = 3599


def _mint(client: Any, client_id: str, scope: str) -> dict:  # noqa: ANN401 - a registered client
    """Store a Bearer token for *client* in ``graph_oauth_tokens`` and answer it.

    The stored record carries the client's ``plan`` and ``licenses``, which
    Graph's feature gates read. The token itself is a signed v1.0 JWT for
    the resource the scope names (:mod:`utils.entra_access_token`), its
    ``roles`` the client's permissions (:func:`utils.entra_app_roles.graph_roles`).
    """
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=_TOKEN_LIFETIME_SECONDS)
    access_token = mint_access_token(
        tenant_id=client.tenant_id,
        client_id=client_id,
        audience=requested_resource(scope),
        roles=graph_roles(client.role, client.plan),
        issued_at=issued_at,
        lifetime_seconds=_TOKEN_LIFETIME_SECONDS,
    )
    store.save("graph_oauth_tokens", access_token, {
        "access_token": access_token,
        "client_id": client_id,
        "tenant_id": client.tenant_id,
        "role": client.role,
        "plan": client.plan,
        "licenses": client.licenses,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    })
    return {
        "token_type": "Bearer",
        "expires_in": _TOKEN_LIFETIME_SECONDS,
        "ext_expires_in": _TOKEN_LIFETIME_SECONDS,
        "access_token": access_token,
    }


router = entra_authority_router(EntraDirectory(
    mount="/graph",
    find_client=graph_oauth_client_repo.get,
    clients=graph_oauth_client_repo.list_all,
    mint=_mint,
    check_scope=lambda scope: require_default_scope(scope, GRAPH_RESOURCES),
), "Graph Auth")
