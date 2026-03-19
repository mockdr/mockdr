"""Build vendor-specific authentication headers for upstream forwarding."""
from __future__ import annotations

import base64
import hashlib
import secrets
import time

from domain.proxy_recording import (
    AuthApiToken,
    AuthBasic,
    AuthHmac,
    AuthOAuth2,
    VendorAuth,
)

from .token_cache import OAuth2TokenCache


async def build_auth_headers(
    vendor: str,
    auth: VendorAuth,
    token_cache: OAuth2TokenCache,
) -> dict[str, str]:
    """Return the HTTP headers needed to authenticate against the real vendor API.

    Args:
        vendor: Vendor key (e.g. ``"crowdstrike"``).
        auth: The auth configuration for the vendor.
        token_cache: Shared OAuth2 token cache for client-credentials vendors.

    Returns:
        Dict of header name -> value.
    """
    if isinstance(auth, AuthApiToken):
        return {"Authorization": f"ApiToken {auth.token}"}

    if isinstance(auth, AuthOAuth2):
        token = await token_cache.get_token(vendor, auth)
        return {"Authorization": f"Bearer {token}"}

    if isinstance(auth, AuthBasic):
        if auth.api_key:
            return {"Authorization": f"ApiKey {auth.api_key}"}
        encoded = base64.b64encode(f"{auth.username}:{auth.password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    if isinstance(auth, AuthHmac):
        nonce = secrets.token_hex(32)
        timestamp = str(int(time.time() * 1000))
        sig = hashlib.sha256(
            f"{auth.key_secret}{nonce}{timestamp}".encode(),
        ).hexdigest()
        return {
            "x-xdr-auth-id": auth.key_id,
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "Authorization": sig,
        }

    return {}
