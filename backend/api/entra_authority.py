"""The Entra authority each Microsoft mount fronts: token, discovery and keys.

Graph, Defender and Sentinel each stand in for ``login.microsoftonline.com``
issuing tokens for their own API. They had three routers with the same four
routes and the same checks in three copies, which had already drifted. One
implementation now serves all three; a mount supplies only what is its own
(:class:`EntraDirectory`): where its clients are registered, which scopes it
issues for, and the token it mints.

The checks, in order:

0. ``grant_type`` is required (AADSTS900144).
1. The client is identified from the form body or from HTTP Basic
   (``client_secret_basic``) -- see :func:`utils.entra_client_auth.resolve_client_credentials`.
2. ``scope`` is required on this grant (AADSTS900144).
3. Only ``client_credentials`` is issued (AADSTS70003).
4. A client ID the directory does not know is ``400 unauthorized_client``
   AADSTS700016; a known one with the wrong secret ``401 invalid_client``
   AADSTS7000215.
5. A tenant-scoped URL must address the client's tenant (AADSTS90002).
6. The mount's own scope rule, if it has one (AADSTS70011).
"""
from __future__ import annotations

import hmac
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request

from utils.entra_client_auth import resolve_client_credentials
from utils.entra_discovery import empty_key_set, openid_configuration, refuse_unhosted_tenant
from utils.entra_tenant import tenant_rejection_message, tenant_segment_matches
from utils.entra_token_errors import (
    AADSTS_INVALID_CLIENT,
    AADSTS_MISSING_PARAMETER,
    AADSTS_TENANT_NOT_FOUND,
    AADSTS_UNSUPPORTED_GRANT,
    build_token_error,
    unknown_client_error,
)


@dataclass(frozen=True)
class EntraDirectory:
    """What one mount's authority holds of its own.

    Attributes:
        mount:       The mount's path prefix, e.g. ``"/graph"``.
        find_client: The registered client with this ID, or None. The client
                     carries ``client_secret``, ``tenant_id`` and
                     ``tenant_domain``.
        clients:     Every registered client, for the tenants the mount hosts.
        mint:        Issue the token: ``(client, client_id, scope) -> body``.
        check_scope: Refuse a scope this mount does not issue for, or None to
                     issue for any scope the request names.
    """

    mount: str
    find_client: Callable[[str], Any]
    clients: Callable[[], Iterable[Any]]
    mint: Callable[[Any, str, str], dict]
    check_scope: Callable[[str], None] | None = None

    def hosted_tenants(self) -> list[tuple[str, str]]:
        """``(tenant_id, tenant_domain)`` of each client the mount holds."""
        return [(c.tenant_id, c.tenant_domain) for c in self.clients()]


def _refuse(status: int, error: str, description: str, code: int) -> HTTPException:
    return HTTPException(status_code=status, detail=build_token_error(error, description, code))


def _require_grant_type(grant_type: str) -> None:
    """Refuse a request that names no grant, before anything else is read.

    Entra answers it as it answers every absent parameter, ``400
    invalid_request`` AADSTS900144 naming the field. Graph and Defender
    declared the field required and answered FastAPI's own wording
    ("grant_type: Field required"); Sentinel answered Entra's.
    """
    if not grant_type:
        raise _refuse(
            400, "invalid_request",
            "AADSTS900144: The request body must contain the following parameter: "
            "'grant_type'.",
            AADSTS_MISSING_PARAMETER,
        )


def issue_token(
    directory: EntraDirectory,
    tenant_id: str | None,
    client_id: str,
    client_secret: str,
    grant_type: str,
    scope: str,
) -> dict:
    """Validate a client-credentials request and mint a token for it.

    Args:
        directory:     The mount's authority.
        tenant_id:     Tenant from the URL, or None on the bare path.
        client_id:     The resolved client ID.
        client_secret: The resolved client secret.
        grant_type:    Must be ``client_credentials``.
        scope:         The resource the token is asked for.

    Returns:
        The mount's token response.

    Raises:
        HTTPException: 400 or 401 in Entra's token-error shape.
    """
    if not scope:
        raise _refuse(
            400, "invalid_request",
            "AADSTS900144: The request body must contain the following parameter: 'scope'.",
            AADSTS_MISSING_PARAMETER,
        )
    if grant_type != "client_credentials":
        raise _refuse(
            400, "unsupported_grant_type",
            "AADSTS70003: The app requested an unsupported grant type. "
            "Only client_credentials is supported.",
            AADSTS_UNSUPPORTED_GRANT,
        )
    client = directory.find_client(client_id)
    if client is None:
        raise HTTPException(
            status_code=400, detail=unknown_client_error(client_id, tenant_id or "common"),
        )
    if not hmac.compare_digest(str(client.client_secret), client_secret):
        raise _refuse(
            401, "invalid_client", "AADSTS7000215: Invalid client secret provided.",
            AADSTS_INVALID_CLIENT,
        )
    if not tenant_segment_matches(tenant_id, client.tenant_id, client.tenant_domain):
        raise _refuse(
            400, "invalid_request", tenant_rejection_message(tenant_id), AADSTS_TENANT_NOT_FOUND,
        )
    if directory.check_scope is not None:
        directory.check_scope(scope)
    return directory.mint(client, client_id, scope)


def entra_authority_router(directory: EntraDirectory, tag: str) -> APIRouter:
    """The four routes of a mount's Entra authority, bound to *directory*."""
    router = APIRouter(tags=[tag])

    @router.post("/oauth2/v2.0/token")
    async def create_token(
        request: Request,
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        grant_type: str = Form(default=""),
        scope: str = Form(default=""),
    ) -> dict:
        """Exchange client credentials for an access token.

        The secret may come in the form body (``client_secret_post``) or in
        an ``Authorization: Basic`` header (``client_secret_basic``); Entra
        requires ``scope`` on this grant.
        """
        _require_grant_type(grant_type)
        client_id, client_secret = resolve_client_credentials(
            request.headers.get("authorization"), client_id, client_secret)
        return issue_token(directory, None, client_id, client_secret, grant_type, scope)

    @router.post("/{tenant_id}/oauth2/v2.0/token")
    async def create_token_for_tenant(
        tenant_id: str,
        request: Request,
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        grant_type: str = Form(default=""),
        scope: str = Form(default=""),
    ) -> dict:
        """Exchange client credentials on the tenant-scoped URL real Entra uses.

        The tenant (GUID or verified domain) must address the credential's
        tenant unless ``MOCKDR_STRICT_TENANT=false``.
        """
        _require_grant_type(grant_type)
        client_id, client_secret = resolve_client_credentials(
            request.headers.get("authorization"), client_id, client_secret)
        return issue_token(directory, tenant_id, client_id, client_secret, grant_type, scope)

    @router.get("/{tenant_id}/v2.0/.well-known/openid-configuration")
    async def openid_configuration_document(tenant_id: str, request: Request) -> dict:
        """The authority's discovery document, which MSAL reads before the token call.

        See :mod:`utils.entra_discovery`. ``token_endpoint`` is this mount's
        own tenant-scoped token route on the host the client called.
        """
        refuse_unhosted_tenant(tenant_id, directory.hosted_tenants())
        return openid_configuration(request, directory.mount, tenant_id)

    @router.get("/{tenant_id}/discovery/v2.0/keys")
    async def signing_keys(tenant_id: str) -> dict:
        """The key set ``jwks_uri`` names -- empty, as the mock's tokens are opaque."""
        refuse_unhosted_tenant(tenant_id, directory.hosted_tenants())
        return empty_key_set()

    return router
