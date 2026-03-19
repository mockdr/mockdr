"""Shared mutable state for the proxy feature (config + recordings list)."""
from __future__ import annotations

from domain.proxy_recording import ProxyConfig, ProxyRecording

from .token_cache import OAuth2TokenCache

_config = ProxyConfig(mode="off")
_recordings: list[ProxyRecording] = []
_token_cache = OAuth2TokenCache()
