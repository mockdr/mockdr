"""Read-only queries for the recording proxy state."""
from __future__ import annotations

import application.proxy._state as _state
from domain.proxy_recording import (
    VENDOR_LABELS,
    AuthApiToken,
    AuthBasic,
    AuthHmac,
    AuthOAuth2,
    ProxyConfig,
    ProxyRecording,
    VendorAuth,
    VendorProxyConfig,
)


def get_config() -> ProxyConfig:
    """Return current proxy configuration with secrets masked."""
    masked_vendors: dict[str, VendorProxyConfig] = {}
    for k, vc in _state._config.vendors.items():
        masked_vendors[k] = VendorProxyConfig(
            vendor=vc.vendor,
            base_url=vc.base_url,
            auth=_mask_auth(vc.auth),
            enabled=vc.enabled,
        )
    return ProxyConfig(
        mode=_state._config.mode,
        vendors=masked_vendors,
        base_url=_state._config.base_url,
        api_token=_mask_token(_state._config.api_token),
    )


def get_config_raw() -> ProxyConfig:
    """Return current proxy configuration with unmasked secrets (internal use)."""
    return _state._config


def get_token_cache() -> object:
    """Return the shared OAuth2 token cache."""
    return _state._token_cache


def list_recordings(vendor: str | None = None) -> list[ProxyRecording]:
    """Return all recordings, newest first. Optionally filter by *vendor*."""
    recs = reversed(_state._recordings)
    if vendor:
        return [r for r in recs if r.vendor == vendor]
    return list(recs)


def find_recording(method: str, path: str, vendor: str | None = None) -> ProxyRecording | None:
    """Return the most recent recording matching method, path, and optionally vendor."""
    for rec in reversed(_state._recordings):
        if rec.method == method and rec.path == path:
            if vendor is None or rec.vendor == vendor:
                return rec
    return None


def recording_count() -> int:
    """Return the total number of stored recordings."""
    return len(_state._recordings)


def vendor_labels() -> dict[str, str]:
    """Return vendor key -> display label mapping."""
    return dict(VENDOR_LABELS)


# ── Masking helpers ──────────────────────────────────────────────────────────

def _mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "***"
    return f"...{token[-8:]}"


def _mask_auth(auth: VendorAuth) -> VendorAuth:
    """Return a copy of *auth* with secrets masked."""
    if isinstance(auth, AuthApiToken):
        return AuthApiToken(token=_mask_token(auth.token))
    if isinstance(auth, AuthOAuth2):
        return AuthOAuth2(
            client_id=auth.client_id,
            client_secret=_mask_token(auth.client_secret),
            token_url=auth.token_url,
        )
    if isinstance(auth, AuthBasic):
        return AuthBasic(
            username=auth.username,
            password=_mask_token(auth.password),
            api_key=_mask_token(auth.api_key),
        )
    if isinstance(auth, AuthHmac):
        return AuthHmac(
            key_id=auth.key_id,
            key_secret=_mask_token(auth.key_secret),
        )
    return auth
