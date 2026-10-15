"""The access tokens the Microsoft mounts issue: signed JWTs, as Entra's are.

Entra's access tokens are JSON web tokens
(https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference:
"Access tokens are JSON web tokens (JWT)"). The mock issued a uuid on
``/graph`` and ``/mde`` and 64 hex digits on ``/sentinel``, so a connector
that reads its token -- ``exp`` to schedule the refresh, ``tid`` to pick the
tenant, ``roles`` to check its consent, ``appid`` and ``oid`` for its own
audit trail -- failed on its first decode against the mock and worked
against Azure.

What a token here carries
-------------------------
Every resource the mock fronts is a Microsoft-owned API that accepts v1.0
tokens -- Microsoft Graph, WindowsDefenderATP, Azure Resource Manager and
the Log Analytics API -- and Entra issues the version the *resource* asks
for, whichever endpoint the client called ("The Microsoft identity platform
supports issuing any token version from any version endpoint",
https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens). So
a client-credentials token from the v2.0 token endpoint is a v1.0 token:

=================  ===========================================================
``aud``            The resource the scope named, ``/.default`` removed (v1.0:
                   "the client ID or the resource URI used in the request")
``iss``, ``idp``   ``https://sts.windows.net/{tid}/`` -- the v1.0 issuer
``iat``, ``nbf``   Five minutes before issue, as Entra backdates them (the
                   reference's v1.0 example has ``exp - iat`` of 3900 for a
                   one-hour token)
``exp``            Issue time plus the response's ``expires_in``
``appid``          The client ID; ``appidacr`` ``"1"``, a client secret
``idtyp``          ``"app"``: an application token, no user
``oid``, ``sub``   The client's service principal (see
                   :func:`service_principal_object_id`)
``roles``          The application permissions granted to the client, when
                   there are any (:mod:`utils.entra_app_roles`)
``tid``            The client's tenant
``uti``            A per-token identifier, 22 base64url characters as Entra's
``ver``            ``"1.0"``
=================  ===========================================================

The header is ``{"typ": "JWT", "alg": "RS256", "x5t": ..., "kid": ...}``:
"x5t ... is a legacy claim emitted only in v1.0 access tokens"; both name
the signing key's thumbprint.

The signing key
---------------
One RSA-2048 key and a self-signed certificate around it, generated the
first time a token is minted and kept for the life of the process; nothing
writes it anywhere, so ``/_dev/export`` and ``MOCKDR_PERSIST`` never see it.
Its public half is served at each mount's ``jwks_uri`` in Entra's keys
document shape (:func:`signing_key_set`).

The key only mints. Whether a token is accepted is still decided by the
mount's token store exactly as before -- the token string is stored at
issue and looked up on every call, so expiry, ``/_dev/reset`` preservation
and persistence across a restart behave as they did. A token issued by an
earlier process (``MOCKDR_PERSIST``) is still accepted, but its signature no
longer verifies against the key set the new process serves -- as a token
signed with a key Entra has since rolled would not.

One deliberate departure: Microsoft Graph's own tokens carry a ``nonce``
header that makes them unverifiable outside Graph ("you can't validate
tokens for Microsoft Graph according to these rules due to their
proprietary format", same page). The mock's Graph tokens verify like any
other, so a test can check them.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

#: Entra backdates ``iat`` and ``nbf`` by five minutes against clock skew.
CLOCK_SKEW_SECONDS = 300

#: The namespace the service principals' object IDs are derived in.
_SERVICE_PRINCIPAL_NAMESPACE = uuid.UUID("6f1b3c1e-6d2a-4c55-9a8e-6d6f636b6472")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64url(value: int) -> str:
    return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


@dataclass(frozen=True)
class SigningKey:
    """The process's token-signing key and the certificate published for it."""

    private_key: rsa.RSAPrivateKey
    certificate_der: bytes

    @property
    def kid(self) -> str:
        """The key ID: the certificate's SHA-1 thumbprint, base64url, as Entra's."""
        # SHA-1 is what x5t is defined as (RFC 7517 section 4.8), not a security choice.
        return _b64url(hashlib.sha1(self.certificate_der, usedforsecurity=False).digest())


_KEY_LOCK = threading.Lock()
_signing_key: SigningKey | None = None


def _generate_signing_key() -> SigningKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mockdr Entra token signing")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return SigningKey(private_key, certificate.public_bytes(serialization.Encoding.DER))


def signing_key() -> SigningKey:
    """The key this process signs with, generated on first use."""
    global _signing_key  # noqa: PLW0603 - one key per process, made once
    with _KEY_LOCK:
        if _signing_key is None:
            _signing_key = _generate_signing_key()
        return _signing_key


def signing_key_set(issuer: str) -> dict:
    """The keys document ``jwks_uri`` serves, in Entra's shape.

    The members are those of ``login.microsoftonline.com/{tenant}/discovery/
    v2.0/keys``: ``kty``, ``use``, ``kid``, ``x5t``, ``n``, ``e``, ``x5c``,
    ``cloud_instance_name`` and the ``issuer`` the key signs for
    (https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens,
    "Keys document and signing key issuer").

    Args:
        issuer: The discovery document's ``issuer`` for this tenant.
    """
    key = signing_key()
    public = key.private_key.public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": key.kid,
        "x5t": key.kid,
        "n": _int_b64url(public.n),
        "e": _int_b64url(public.e),
        "x5c": [base64.b64encode(key.certificate_der).decode("ascii")],
        "cloud_instance_name": "microsoftonline.com",
        "issuer": issuer,
    }]}


def service_principal_object_id(tenant_id: str, client_id: str) -> str:
    """The object ID of a client's service principal in its tenant.

    An app-only token's ``oid`` and ``sub`` are the service principal's
    object ID: "the verified identity of the user or service principal" --
    one per application per tenant. Derived from the two, so it is the same
    for a seeded client in every process and after every reset.
    """
    return str(uuid.uuid5(_SERVICE_PRINCIPAL_NAMESPACE, f"{tenant_id}/{client_id}"))


def requested_resource(scope: str) -> str:
    """The resource a client-credentials ``scope`` names: its first scope without ``/.default``."""
    first = scope.split()[0] if scope.split() else ""
    return first.removesuffix("/.default")


def mint_access_token(
    *,
    tenant_id: str,
    client_id: str,
    audience: str,
    roles: list[str],
    issued_at: datetime,
    lifetime_seconds: int,
) -> str:
    """Sign a v1.0 app-only access token for *client_id*.

    Args:
        tenant_id:        The client's tenant (``tid``, and in ``iss``).
        client_id:        The client's application ID (``appid``).
        audience:         The resource the token is for (``aud``).
        roles:            The application permissions; no ``roles`` claim when empty.
        issued_at:        When the token is issued; ``exp`` is this plus the lifetime.
        lifetime_seconds: The ``expires_in`` the token response carries.

    Returns:
        The compact JWS: ``header.payload.signature``.
    """
    key = signing_key()
    issued = int(issued_at.timestamp())
    issuer = f"https://sts.windows.net/{tenant_id}/"
    principal = service_principal_object_id(tenant_id, client_id)
    claims: dict[str, object] = {
        "aud": audience,
        "iss": issuer,
        "iat": issued - CLOCK_SKEW_SECONDS,
        "nbf": issued - CLOCK_SKEW_SECONDS,
        "exp": issued + lifetime_seconds,
        "appid": client_id,
        "appidacr": "1",
        "idp": issuer,
        "idtyp": "app",
        "oid": principal,
    }
    if roles:
        claims["roles"] = list(roles)
    claims.update({
        "sub": principal,
        "tid": tenant_id,
        "uti": _b64url(secrets.token_bytes(16)),
        "ver": "1.0",
    })
    header = {"typ": "JWT", "alg": "RS256", "x5t": key.kid, "kid": key.kid}
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    signature = key.private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"
