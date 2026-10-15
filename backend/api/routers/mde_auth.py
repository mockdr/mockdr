"""Microsoft Defender for Endpoint OAuth2 token endpoint.

Implements the Azure AD client credentials flow: clients POST ``client_id``,
``client_secret``, and ``grant_type=client_credentials`` as form-encoded data
and receive a time-limited Bearer token.

Pre-seeded mock credentials (seeded via ``infrastructure/seeders/mde_oauth.py``):

* Admin:   ``mde-mock-admin-client`` / ``mde-mock-admin-secret``
* Analyst: ``mde-mock-analyst-client`` / ``mde-mock-analyst-secret``
* Viewer:  ``mde-mock-viewer-client`` / ``mde-mock-viewer-secret``
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from api.entra_authority import EntraDirectory, entra_authority_router
from repository.mde_oauth_client_repo import mde_oauth_client_repo
from repository.store import store
from utils.entra_access_token import mint_access_token, requested_resource
from utils.entra_app_roles import mde_roles
from utils.entra_client_auth import MDE_RESOURCES, require_default_scope

_TOKEN_LIFETIME_SECONDS: int = 3599


def _mint(client: Any, client_id: str, scope: str) -> dict:  # noqa: ANN401 - a registered client
    """Store a Bearer token for *client* in ``mde_oauth_tokens`` and answer it.

    The token is a signed v1.0 JWT for the resource the scope names
    (:mod:`utils.entra_access_token`), its ``roles`` the client's
    WindowsDefenderATP permissions (:func:`utils.entra_app_roles.mde_roles`).
    """
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=_TOKEN_LIFETIME_SECONDS)
    access_token = mint_access_token(
        tenant_id=client.tenant_id,
        client_id=client_id,
        audience=requested_resource(scope),
        roles=mde_roles(client.role),
        issued_at=issued_at,
        lifetime_seconds=_TOKEN_LIFETIME_SECONDS,
    )
    store.save("mde_oauth_tokens", access_token, {
        "access_token": access_token,
        "client_id": client_id,
        "tenant_id": client.tenant_id,
        "role": client.role,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    })
    return {
        "token_type": "Bearer",
        "expires_in": _TOKEN_LIFETIME_SECONDS,
        "ext_expires_in": _TOKEN_LIFETIME_SECONDS,
        "access_token": access_token,
    }


router = entra_authority_router(EntraDirectory(
    mount="/mde",
    find_client=mde_oauth_client_repo.get_by_client_id,
    clients=mde_oauth_client_repo.list_all,
    mint=_mint,
    check_scope=lambda scope: require_default_scope(scope, MDE_RESOURCES),
), "MDE Auth")
