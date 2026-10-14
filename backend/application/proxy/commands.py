"""Write-only commands for the recording proxy feature."""
from __future__ import annotations

import application.proxy._state as _state
import config
from domain.proxy_recording import (
    VENDOR_NAMES,
    AuthApiToken,
    AuthBasic,
    AuthHmac,
    AuthOAuth2,
    ProxyConfig,
    ProxyRecording,
    VendorAuth,
    VendorProxyConfig,
)
from utils.egress import check_outbound_url

_VALID_MODES = frozenset({"off", "record", "replay"})
_MAX_RECORDINGS = 1000


def set_config(
    mode: str,
    vendors: list[dict[str, object]] | None = None,
    *,
    # Legacy flat params for backward compat.
    base_url: str = "",
    api_token: str = "",
) -> ProxyConfig:
    """Update proxy mode and optional per-vendor connection settings.

    Args:
        mode: One of ``"off"``, ``"record"``, or ``"replay"``.
        vendors: Optional list of vendor config dicts.
        base_url: Legacy S1-only base URL.
        api_token: Legacy S1-only API token.

    Returns:
        The updated ``ProxyConfig``.

    Raises:
        ValueError: If ``mode`` or a vendor name is invalid, or an upstream
            or token URL is not one the mock may send a request to.
        PermissionError: If the proxy is switched on on a public instance.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {sorted(_VALID_MODES)}")
    if mode != "off" and config.PUBLIC_MODE:
        # Record mode forwards anonymous requests to an upstream the caller
        # names, with credentials attached: on a public instance that is an
        # open proxy into the host's network. Replay has nothing to serve
        # without it.
        raise PermissionError(
            "the recording proxy is disabled on a public instance (MOCKDR_PUBLIC)",
        )

    # Start from current vendor configs.
    new_vendors = dict(_state._config.vendors)

    # Handle per-vendor configs if provided.
    if vendors:
        for v in vendors:
            vendor_name = str(v.get("vendor", ""))
            if vendor_name not in VENDOR_NAMES:
                valid = sorted(VENDOR_NAMES)
                raise ValueError(f"Unknown vendor '{vendor_name}'. Must be one of: {valid}")
            auth = _parse_auth(v.get("auth", {}))
            vendor_url = str(v.get("base_url", "")).rstrip("/")
            _check_target(vendor_url)
            if isinstance(auth, AuthOAuth2):
                _check_target(auth.token_url)
            new_vendors[vendor_name] = VendorProxyConfig(
                vendor=vendor_name,
                base_url=vendor_url,
                auth=auth,
                enabled=bool(v.get("enabled", True)),
            )

    # Legacy flat S1 config: migrate into per-vendor dict.
    if base_url or api_token:
        _check_target(base_url.rstrip("/"))
        existing = new_vendors.get("s1")
        prev_url = existing.base_url if existing else ""
        prev_token = (
            existing.auth.token
            if existing and isinstance(existing.auth, AuthApiToken)
            else ""
        )
        new_vendors["s1"] = VendorProxyConfig(
            vendor="s1",
            base_url=base_url.rstrip("/") if base_url else prev_url,
            auth=AuthApiToken(token=api_token if api_token else prev_token),
            enabled=True,
        )

    # Extract legacy flat fields for backward compat.
    s1_cfg = new_vendors.get("s1")
    legacy_url = s1_cfg.base_url if s1_cfg else ""
    legacy_token = (
        s1_cfg.auth.token
        if s1_cfg and isinstance(s1_cfg.auth, AuthApiToken)
        else ""
    )
    _state._config = ProxyConfig(
        mode=mode,
        vendors=new_vendors,
        base_url=legacy_url,
        api_token=legacy_token,
    )
    return _state._config


def _check_target(url: str) -> None:
    """Refuse an upstream the mock may not send to; an empty one is unset."""
    if url:
        # Names are resolved again before each forwarded request.
        check_outbound_url(url, resolve=False)


def add_recording(recording: ProxyRecording) -> None:
    """Append a new recording to the in-memory list."""
    _state._recordings.append(recording)
    if len(_state._recordings) > _MAX_RECORDINGS:
        _state._recordings = _state._recordings[-_MAX_RECORDINGS:]


def clear_recordings() -> int:
    """Remove all recordings. Returns the count removed."""
    count = len(_state._recordings)
    _state._recordings.clear()
    return count


def _parse_auth(raw: object) -> VendorAuth:
    """Convert a raw dict from the API into the appropriate auth dataclass."""
    if not isinstance(raw, dict):
        return AuthApiToken()
    auth_type = str(raw.get("type", "api_token"))
    if auth_type == "oauth2":
        return AuthOAuth2(
            client_id=str(raw.get("client_id", "")),
            client_secret=str(raw.get("client_secret", "")),
            token_url=str(raw.get("token_url", "")),
        )
    if auth_type == "basic":
        return AuthBasic(
            username=str(raw.get("username", "")),
            password=str(raw.get("password", "")),
            api_key=str(raw.get("api_key", "")),
        )
    if auth_type == "hmac":
        return AuthHmac(
            key_id=str(raw.get("key_id", "")),
            key_secret=str(raw.get("key_secret", "")),
        )
    # Default: api_token
    return AuthApiToken(token=str(raw.get("token", "")))
