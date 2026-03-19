"""OAuth2 Bearer token cache for vendors using client credentials flow."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from domain.proxy_recording import AuthOAuth2


@dataclass
class _CachedToken:
    access_token: str
    expires_at: float  # monotonic clock


class OAuth2TokenCache:
    """Thread-safe cache for OAuth2 Bearer tokens, keyed by vendor name.

    Tokens are refreshed automatically when they are within 30 seconds of
    expiry or missing entirely.
    """

    _SAFETY_MARGIN = 30.0  # seconds before actual expiry to trigger refresh

    def __init__(self) -> None:
        """Initialize an empty token cache."""
        self._tokens: dict[str, _CachedToken] = {}
        self._lock = asyncio.Lock()

    async def get_token(self, vendor: str, auth: AuthOAuth2) -> str:
        """Return a valid Bearer token, fetching/refreshing as needed."""
        async with self._lock:
            cached = self._tokens.get(vendor)
            if cached and time.monotonic() < cached.expires_at - self._SAFETY_MARGIN:
                return cached.access_token

            # Token expired or missing -- exchange credentials.
            token = await self._fetch_token(auth)
            return token.access_token

    async def _fetch_token(self, auth: AuthOAuth2) -> _CachedToken:
        """POST to the vendor's token endpoint and cache the result."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                auth.token_url,
                data={
                    "client_id": auth.client_id,
                    "client_secret": auth.client_secret,
                    "grant_type": "client_credentials",
                },
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()

        token = _CachedToken(
            access_token=data["access_token"],
            expires_at=time.monotonic() + data.get("expires_in", 3600),
        )
        # Caller already holds the lock.
        vendor_key = auth.token_url  # unique per vendor+tenant
        self._tokens[vendor_key] = token
        return token

    def invalidate(self, vendor: str) -> None:
        """Remove cached token for *vendor* (e.g. after a 401)."""
        self._tokens.pop(vendor, None)

    def clear(self) -> None:
        """Remove all cached tokens."""
        self._tokens.clear()
