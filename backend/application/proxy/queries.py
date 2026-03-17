"""Read-only queries for the recording proxy state."""
from __future__ import annotations

import application.proxy._state as _state
from domain.proxy_recording import ProxyConfig, ProxyRecording


def get_config() -> ProxyConfig:
    """Return current proxy configuration (api_token is masked)."""
    return ProxyConfig(
        mode=_state._config.mode,
        base_url=_state._config.base_url,
        api_token=_mask_token(_state._config.api_token),
    )


def get_config_raw() -> ProxyConfig:
    """Return current proxy configuration with the unmasked token (internal use only)."""
    return _state._config


def list_recordings() -> list[ProxyRecording]:
    """Return all recordings, newest first."""
    return list(reversed(_state._recordings))


def find_recording(method: str, path: str) -> ProxyRecording | None:
    """Return the most recent recording matching the given method and path."""
    for rec in reversed(_state._recordings):
        if rec.method == method and rec.path == path:
            return rec
    return None


def recording_count() -> int:
    """Return the total number of stored recordings."""
    return len(_state._recordings)


def _mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "***"
    return f"...{token[-8:]}"
