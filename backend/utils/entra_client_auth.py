"""How a client-credentials request identifies the client, and what it asks for.

Shared by the Graph and Defender token endpoints, which stand in for
``login.microsoftonline.com``.

Client authentication. Entra takes the secret in the form body
(``client_secret_post``) or in the ``Authorization`` header: "The Basic auth
pattern of instead providing credentials in the Authorization header, per
RFC 6749 is also supported"
(https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow),
and the tenant discovery document lists ``client_secret_basic`` among its
``token_endpoint_auth_methods_supported``. Both mounts declared the secret a
required form field, so a client using HTTP Basic -- the default of many
generic OAuth libraries -- was refused before its credentials were read.

Scope. "The value passed for the scope parameter in this request should be
the resource identifier (application ID URI) of the resource you want,
suffixed with .default. All scopes included must be for a single resource"
(same page), and an invalid one is ``400 invalid_scope`` with
``AADSTS70011: The provided value for the input parameter 'scope' is not
valid. The scope ... is not valid.`` (the page's own error example). Both
mounts accepted any non-empty string, so ``scope=x`` minted a working token.

One deliberate departure: real Entra would issue a token for any resource the
app is consented to, and the API would then refuse it for its audience. Here
each mount's token endpoint stands in for Entra issuing tokens *for that
API*, so a scope naming another resource -- a Graph scope sent to the
Defender mount -- is refused at the token endpoint with the same
``invalid_scope`` rather than producing a token the mount would accept.
"""
from __future__ import annotations

import base64
import binascii
from urllib.parse import unquote_plus

from fastapi import HTTPException

from utils.entra_token_errors import (
    AADSTS_INVALID_CLIENT,
    AADSTS_INVALID_SCOPE,
    AADSTS_MISSING_PARAMETER,
    build_token_error,
)

#: The resource identifiers the Graph mount issues tokens for: the documented
#: URI, and Microsoft Graph's well-known application ID.
GRAPH_RESOURCES = (
    "https://graph.microsoft.com",
    "00000003-0000-0000-c000-000000000000",
)

#: The resource identifiers the Defender mount issues tokens for. The legacy
#: ``api.securitycenter.microsoft.com`` is the one the docs tell callers to
#: request (https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp);
#: ``api.security.microsoft.com`` is the host the API pages now show;
#: ``windowsatpservice`` and the WindowsDefenderATP application ID are the
#: older identifiers of the same service principal.
MDE_RESOURCES = (
    "https://api.securitycenter.microsoft.com",
    "https://api.security.microsoft.com",
    "https://securitycenter.onmicrosoft.com/windowsatpservice",
    "fc780465-2017-40d4-a0c5-307022471b92",
)

_DEFAULT_SUFFIX = "/.default"


def _missing(name: str) -> HTTPException:
    return HTTPException(status_code=400, detail=build_token_error(
        "invalid_request",
        f"AADSTS900144: The request body must contain the following parameter: '{name}'.",
        AADSTS_MISSING_PARAMETER,
    ))


def resolve_client_credentials(
    authorization: str | None, client_id: str, client_secret: str,
) -> tuple[str, str]:
    """The client ID and secret, from the form body or from HTTP Basic.

    RFC 6749 §2.3.1: the Basic credentials are the client ID and secret, each
    form-urlencoded, joined by a colon. A ``client_id`` in the body alongside
    the header is overridden by it.

    Args:
        authorization: The ``Authorization`` header, if any.
        client_id:     ``client_id`` from the form body, or empty.
        client_secret: ``client_secret`` from the form body, or empty.

    Returns:
        The client ID and secret to check.

    Raises:
        HTTPException: 400 when either is missing from both places; 401
            when the header is not decodable Basic credentials.
    """
    if authorization and authorization[:6].lower() == "basic ":
        try:
            decoded = base64.b64decode(authorization[6:].strip(), validate=True).decode()
            basic_id, _, basic_secret = decoded.partition(":")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=401, detail=build_token_error(
                "invalid_client",
                "AADSTS7000215: Invalid client secret provided.",
                AADSTS_INVALID_CLIENT,
            )) from exc
        # The header names the client; a body that also carries one is using
        # two methods at once, which RFC 6749 forbids and Entra does not
        # document, so the header is the one believed.
        client_id = unquote_plus(basic_id)
        client_secret = client_secret or unquote_plus(basic_secret)
    if not client_id:
        raise _missing("client_id")
    if not client_secret:
        raise _missing("client_secret")
    return client_id, client_secret


def _invalid_scope(scope: str) -> HTTPException:
    return HTTPException(status_code=400, detail=build_token_error(
        "invalid_scope",
        f"AADSTS70011: The provided value for the input parameter 'scope' is not valid. "
        f"The scope {scope} is not valid.",
        AADSTS_INVALID_SCOPE,
    ))


def require_default_scope(scope: str, resources: tuple[str, ...]) -> None:
    """Refuse a client-credentials scope Entra would not issue this mount a token for.

    Each space-separated scope must be ``{resource}/.default``, they must all
    name one resource, and that resource must be one of ``resources``.
    Identifiers compare case-insensitively and ignore a trailing slash
    (``https://graph.microsoft.com//.default`` is the documented spelling for
    a URI that ends in one).

    Raises:
        HTTPException: 400 ``invalid_scope`` (AADSTS70011).
    """
    accepted = {r.lower().rstrip("/") for r in resources}
    named: set[str] = set()
    for item in scope.split():
        if not item.lower().endswith(_DEFAULT_SUFFIX):
            raise _invalid_scope(scope)
        named.add(item[: -len(_DEFAULT_SUFFIX)].lower().rstrip("/"))
    if len(named) != 1 or not named <= accepted:
        raise _invalid_scope(scope)
