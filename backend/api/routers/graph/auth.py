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

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Form, HTTPException, Request

from repository.graph.oauth_client_repo import graph_oauth_client_repo
from repository.store import store
from utils.entra_client_auth import (
    GRAPH_RESOURCES,
    require_default_scope,
    resolve_client_credentials,
)
from utils.entra_discovery import (
    empty_key_set,
    openid_configuration,
    refuse_unhosted_tenant,
)
from utils.entra_tenant import tenant_rejection_message, tenant_segment_matches
from utils.entra_token_errors import (
    AADSTS_INVALID_CLIENT,
    AADSTS_MISSING_PARAMETER,
    AADSTS_TENANT_NOT_FOUND,
    AADSTS_UNSUPPORTED_GRANT,
    build_token_error,
    unknown_client_error,
)

router = APIRouter(tags=["Graph Auth"])

_TOKEN_LIFETIME_SECONDS: int = 3599


@router.post("/oauth2/v2.0/token")
async def create_token(
    request: Request,
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    grant_type: str = Form(...),
    scope: str = Form(default=""),
) -> dict:
    """Exchange client credentials for an access token.

    Args:
        request:       Read for an ``Authorization: Basic`` header, the
                       ``client_secret_basic`` method Entra also accepts.
        client_id:     OAuth2 client identifier (form-encoded, or Basic).
        client_secret: OAuth2 client secret (form-encoded, or Basic).
        grant_type:    Must be ``"client_credentials"``.
        scope:         The resource being asked for. Entra requires it on
                       this grant and refuses a request without one.

    Returns:
        Token response — see :func:`_issue_token`.
    """
    client_id, client_secret = resolve_client_credentials(
        request.headers.get("authorization"), client_id, client_secret)
    return _issue_token(None, client_id, client_secret, grant_type, scope)


@router.post("/{tenant_id}/oauth2/v2.0/token")
async def create_token_for_tenant(
    tenant_id: str,
    request: Request,
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    grant_type: str = Form(...),
    scope: str = Form(default=""),
) -> dict:
    """Exchange client credentials on the tenant-scoped URL real Entra uses.

    Args:
        tenant_id:     Tenant GUID or verified domain name from the URL. Must
                       address the credential's tenant unless
                       ``MOCKDR_STRICT_TENANT=false``.
        request:       Read for an ``Authorization: Basic`` header, the
                       ``client_secret_basic`` method Entra also accepts.
        client_id:     OAuth2 client identifier (form-encoded, or Basic).
        client_secret: OAuth2 client secret (form-encoded, or Basic).
        grant_type:    Must be ``"client_credentials"``.
        scope:         The resource being asked for. Entra requires it on
                       this grant and refuses a request without one.

    Returns:
        Token response — see :func:`_issue_token`.
    """
    client_id, client_secret = resolve_client_credentials(
        request.headers.get("authorization"), client_id, client_secret)
    return _issue_token(tenant_id, client_id, client_secret, grant_type, scope)


def _issue_token(
    tenant_id: str | None,
    client_id: str,
    client_secret: str,
    grant_type: str,
    scope: str = "",
) -> dict:
    """Validate a client-credentials request and mint an access token.

    Validates the ``grant_type`` is ``client_credentials``, checks the
    credentials against the ``graph_oauth_clients`` repository, generates a
    Bearer token, stores it in ``graph_oauth_tokens`` with expiration, and
    returns the token in Azure AD format.

    Args:
        tenant_id:     Tenant from the URL, or ``None`` on the bare path.
        client_id:     OAuth2 client identifier.
        client_secret: OAuth2 client secret.
        grant_type:    Must be ``"client_credentials"``.
        scope:         The resource being asked for. Entra requires it on
                       this grant and refuses a request without one.

    Returns:
        Dict with ``access_token``, ``token_type``, ``expires_in``, and
        ``ext_expires_in``.

    Raises:
        HTTPException: 400 if grant_type is invalid, the tenant is unknown,
            the client ID names no application (AADSTS700016), or the scope is
            not this API's ``/.default`` (AADSTS70011).
        HTTPException: 401 if the secret is wrong.
    """
    if not scope:
        raise HTTPException(status_code=400, detail=build_token_error(
            "invalid_request",
            "AADSTS900144: The request body must contain the following "
            "parameter: 'scope'.",
            AADSTS_MISSING_PARAMETER,
        ))

    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail=build_token_error(
                "unsupported_grant_type",
                "AADSTS70003: The app requested an unsupported grant type. "
                "Only client_credentials is supported.",
                AADSTS_UNSUPPORTED_GRANT,
            ),
        )

    client = graph_oauth_client_repo.get(client_id)
    if client is None:
        raise HTTPException(
            status_code=400,
            detail=unknown_client_error(client_id, tenant_id or "common"),
        )
    if client.client_secret != client_secret:
        raise HTTPException(
            status_code=401,
            detail=build_token_error(
                "invalid_client",
                "AADSTS7000215: Invalid client secret provided.",
                AADSTS_INVALID_CLIENT,
            ),
        )

    if not tenant_segment_matches(tenant_id, client.tenant_id, client.tenant_domain):
        raise HTTPException(
            status_code=400,
            detail=build_token_error(
                "invalid_request",
                tenant_rejection_message(tenant_id),
                AADSTS_TENANT_NOT_FOUND,
            ),
        )

    require_default_scope(scope, GRAPH_RESOURCES)

    access_token = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(seconds=_TOKEN_LIFETIME_SECONDS)

    token_record: dict = {
        "access_token": access_token,
        "client_id": client_id,
        "tenant_id": client.tenant_id,
        "role": client.role,
        "plan": client.plan,
        "licenses": client.licenses,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    store.save("graph_oauth_tokens", access_token, token_record)

    return {
        "token_type": "Bearer",
        "expires_in": _TOKEN_LIFETIME_SECONDS,
        "ext_expires_in": _TOKEN_LIFETIME_SECONDS,
        "access_token": access_token,
    }


# ---------------------------------------------------------------------------
# OpenID Connect discovery
# ---------------------------------------------------------------------------

@router.get("/{tenant_id}/v2.0/.well-known/openid-configuration")
async def openid_configuration_document(tenant_id: str, request: Request) -> dict:
    """The authority's discovery document, which MSAL reads before the token call.

    See :mod:`utils.entra_discovery`. ``token_endpoint`` is this mount's own
    tenant-scoped token route on the host the client called.
    """
    refuse_unhosted_tenant(tenant_id, _hosted_tenants())
    return openid_configuration(request, "/graph", tenant_id)


@router.get("/{tenant_id}/discovery/v2.0/keys")
async def signing_keys(tenant_id: str) -> dict:
    """The key set ``jwks_uri`` names -- empty, as Graph mock tokens are opaque."""
    refuse_unhosted_tenant(tenant_id, _hosted_tenants())
    return empty_key_set()


def _hosted_tenants() -> list[tuple[str, str]]:
    """The tenants this mount's clients belong to, as ``(id, domain)``."""
    return [(c.tenant_id, c.tenant_domain) for c in graph_oauth_client_repo.list_all()]
