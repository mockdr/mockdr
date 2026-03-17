"""Write-only commands for the recording proxy feature."""
from __future__ import annotations

import application.proxy._state as _state
from domain.proxy_recording import ProxyConfig, ProxyRecording

_VALID_MODES = frozenset({"off", "record", "replay"})
_MAX_RECORDINGS = 1000


def set_config(mode: str, base_url: str = "", api_token: str = "") -> ProxyConfig:
    """Update proxy mode and optional connection settings.

    Args:
        mode: One of ``"off"``, ``"record"``, or ``"replay"``.
        base_url: Real S1 management console base URL (e.g. ``https://tenant.sentinelone.net/web/api/v2.1``).
        api_token: Real S1 API token used when forwarding requests.

    Returns:
        The updated ``ProxyConfig`` with the token masked.

    Raises:
        ValueError: If ``mode`` is not a valid mode string.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {sorted(_VALID_MODES)}")
    _state._config = ProxyConfig(
        mode=mode,
        base_url=base_url.rstrip("/") if base_url else _state._config.base_url,
        api_token=api_token if api_token else _state._config.api_token,
    )
    return _state._config


def add_recording(recording: ProxyRecording) -> None:
    """Append a new recording to the in-memory list.

    Args:
        recording: The ``ProxyRecording`` to store.
    """
    _state._recordings.append(recording)
    if len(_state._recordings) > _MAX_RECORDINGS:
        _state._recordings = _state._recordings[-_MAX_RECORDINGS:]


def clear_recordings() -> int:
    """Remove all recordings.

    Returns:
        The number of recordings that were removed.
    """
    count = len(_state._recordings)
    _state._recordings.clear()
    return count
