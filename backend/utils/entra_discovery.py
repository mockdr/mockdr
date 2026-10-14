"""The OpenID Connect discovery document an Entra authority publishes.

MSAL and azure-identity do not start with the token call: they first fetch
``{authority}/v2.0/.well-known/openid-configuration`` and read
``token_endpoint`` from it
(https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc:
"append the well-known OpenID configuration path to your app registration's
authority URL"). The mock served no such document, so neither library could
use a mockdr mount as its authority -- a client had to hand-roll the token
request to test against it at all.

Each Entra-fronted mount now serves the document under
``/{mount}/{tenant}/v2.0/.well-known/openid-configuration``, with every
endpoint built from the URL the client called, so ``token_endpoint`` points
back at the mount's own tenant-scoped token route. The field names and the
fixed values (``subject_types_supported``, the signing algorithm, the auth
methods) are those of ``login.microsoftonline.com``'s own document.

Tokens stay opaque: ``jwks_uri`` answers an empty key set, because there is
no signature for a client to check.
"""
from __future__ import annotations

from starlette.requests import Request

from utils.entra_tenant import ENTRA_TENANT_ALIASES


def openid_configuration(request: Request, mount: str, tenant: str) -> dict:
    """The discovery document for ``tenant`` on ``mount``.

    Args:
        request: The discovery request, read for the base URL.
        mount:   The mount prefix, e.g. ``/graph``.
        tenant:  The tenant segment from the URL, a GUID, a domain or an alias.

    Returns:
        The OpenID Provider metadata.
    """
    base = str(request.base_url).rstrip("/")
    authority = f"{base}{mount}/{tenant}"
    # Entra's multi-tenant documents leave the issuer's tenant as a template.
    issuer_tenant = "{tenantid}" if tenant.casefold() in ENTRA_TENANT_ALIASES else tenant
    return {
        "token_endpoint": f"{authority}/oauth2/v2.0/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_post", "private_key_jwt", "client_secret_basic",
        ],
        "jwks_uri": f"{authority}/discovery/v2.0/keys",
        "response_modes_supported": ["query", "fragment", "form_post"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code", "id_token", "code id_token", "id_token token"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "issuer": f"{base}{mount}/{issuer_tenant}/v2.0",
        "request_uri_parameter_supported": False,
        "authorization_endpoint": f"{authority}/oauth2/v2.0/authorize",
        "device_authorization_endpoint": f"{authority}/oauth2/v2.0/devicecode",
        "end_session_endpoint": f"{authority}/oauth2/v2.0/logout",
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "acr", "nonce",
            "preferred_username", "name", "tid", "ver", "at_hash", "c_hash", "email",
        ],
        "tenant_region_scope": None,
        "cloud_instance_name": "microsoftonline.com",
        "msgraph_host": "graph.microsoft.com",
    }


def empty_key_set() -> dict:
    """The JSON Web Key Set behind ``jwks_uri``: none, as tokens are opaque."""
    return {"keys": []}
