"""Shared mutable state for the proxy feature (config + recordings list)."""
from __future__ import annotations

import os

from domain.proxy_recording import ProxyConfig, ProxyRecording

_config = ProxyConfig(
    mode="off",
    base_url=os.environ.get("BASE_URL", "").rstrip("/"),
    api_token=os.environ.get("API_KEY", ""),
)
_recordings: list[ProxyRecording] = []
