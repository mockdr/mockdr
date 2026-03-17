"""Domain types for the recording proxy feature."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProxyRecording:
    """A single recorded request/response exchange with the real S1 API."""

    id: str
    method: str
    path: str
    query_string: str
    request_body: str
    response_status: int
    response_body: str
    response_content_type: str
    recorded_at: str
    base_url: str


@dataclass
class ProxyConfig:
    """Current proxy mode and upstream connection settings."""

    mode: str = "off"      # "off" | "record" | "replay"
    base_url: str = ""     # real S1 management console base URL
    api_token: str = ""    # real S1 API token (masked in API responses)
