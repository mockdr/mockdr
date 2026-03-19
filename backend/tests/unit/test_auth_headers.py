"""Unit tests for per-vendor auth header building."""
from __future__ import annotations

import base64
from unittest.mock import AsyncMock, patch

import pytest

from application.proxy.auth_headers import build_auth_headers
from application.proxy.token_cache import OAuth2TokenCache
from domain.proxy_recording import AuthApiToken, AuthBasic, AuthHmac, AuthOAuth2


@pytest.fixture
def token_cache() -> OAuth2TokenCache:
    return OAuth2TokenCache()


class TestBuildAuthHeaders:
    @pytest.mark.asyncio
    async def test_api_token(self, token_cache: OAuth2TokenCache) -> None:
        auth = AuthApiToken(token="my-s1-token")
        headers = await build_auth_headers("s1", auth, token_cache)
        assert headers == {"Authorization": "ApiToken my-s1-token"}

    @pytest.mark.asyncio
    async def test_oauth2(self, token_cache: OAuth2TokenCache) -> None:
        auth = AuthOAuth2(
            client_id="cid",
            client_secret="csecret",
            token_url="https://api.example.com/oauth2/token",
        )
        with patch.object(token_cache, "get_token", new_callable=AsyncMock, return_value="mock-bearer-token"):
            headers = await build_auth_headers("crowdstrike", auth, token_cache)
        assert headers == {"Authorization": "Bearer mock-bearer-token"}

    @pytest.mark.asyncio
    async def test_basic_auth(self, token_cache: OAuth2TokenCache) -> None:
        auth = AuthBasic(username="elastic", password="changeme")
        headers = await build_auth_headers("elastic", auth, token_cache)
        expected = base64.b64encode(b"elastic:changeme").decode()
        assert headers == {"Authorization": f"Basic {expected}"}

    @pytest.mark.asyncio
    async def test_api_key_auth(self, token_cache: OAuth2TokenCache) -> None:
        auth = AuthBasic(api_key="my-api-key")
        headers = await build_auth_headers("elastic", auth, token_cache)
        assert headers == {"Authorization": "ApiKey my-api-key"}

    @pytest.mark.asyncio
    async def test_hmac_auth(self, token_cache: OAuth2TokenCache) -> None:
        auth = AuthHmac(key_id="1", key_secret="xdr-admin-secret")
        headers = await build_auth_headers("cortex_xdr", auth, token_cache)
        assert headers["x-xdr-auth-id"] == "1"
        assert "x-xdr-nonce" in headers
        assert "x-xdr-timestamp" in headers
        assert "Authorization" in headers
        # Nonce should be 64 hex chars (32 bytes).
        assert len(headers["x-xdr-nonce"]) == 64
