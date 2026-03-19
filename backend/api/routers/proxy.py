"""Recording proxy management endpoints.

GET    /_dev/proxy/config       — get current proxy mode and per-vendor settings
POST   /_dev/proxy/config       — set mode, per-vendor upstream configs
GET    /_dev/proxy/recordings   — list all recorded exchanges
DELETE /_dev/proxy/recordings   — clear all recordings
GET    /_dev/proxy/vendors      — list supported vendor names and labels
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from api.dto.requests import ProxyConfigBody
from application.proxy import commands as proxy_commands
from application.proxy import queries as proxy_queries
from domain.proxy_recording import (
    VENDOR_DEFAULT_AUTH,
    AuthApiToken,
    AuthBasic,
    AuthHmac,
    AuthOAuth2,
    VendorAuth,
)

router = APIRouter(tags=["Proxy"])


def _serialize_auth(auth: VendorAuth) -> dict[str, object]:
    """Convert an auth dataclass to a JSON-safe dict."""
    if isinstance(auth, AuthApiToken):
        return {"type": "api_token", "token": auth.token}
    if isinstance(auth, AuthOAuth2):
        return {
            "type": "oauth2",
            "client_id": auth.client_id,
            "client_secret": auth.client_secret,
            "token_url": auth.token_url,
        }
    if isinstance(auth, AuthBasic):
        return {
            "type": "basic",
            "username": auth.username,
            "password": auth.password,
            "api_key": auth.api_key,
        }
    if isinstance(auth, AuthHmac):
        return {
            "type": "hmac",
            "key_id": auth.key_id,
            "key_secret": auth.key_secret,
        }
    return {"type": "unknown"}


def _serialize_config(masked: bool = True) -> dict[str, object]:
    """Build the JSON response for the proxy config."""
    cfg = proxy_queries.get_config() if masked else proxy_queries.get_config_raw()
    vendors_out: dict[str, object] = {}
    for k, vc in cfg.vendors.items():
        vendors_out[k] = {
            "vendor": vc.vendor,
            "base_url": vc.base_url,
            "auth": _serialize_auth(vc.auth),
            "enabled": vc.enabled,
        }
    return {
        "data": {
            "mode": cfg.mode,
            "vendors": vendors_out,
            "recording_count": proxy_queries.recording_count(),
            # Legacy flat fields for backward compat.
            "base_url": cfg.base_url,
            "api_token": proxy_queries.get_config().api_token if not masked else cfg.api_token,
        }
    }


@router.get("/_dev/proxy/config")
def get_proxy_config() -> dict[str, object]:
    """Return current proxy configuration (secrets masked)."""
    return _serialize_config(masked=True)


@router.post("/_dev/proxy/config")
def set_proxy_config(body: ProxyConfigBody, _: dict = Depends(require_admin)) -> dict[str, object]:
    """Update proxy mode and optionally per-vendor upstream connection settings.

    Accepts both the new ``vendors`` list and the legacy flat ``base_url``/``api_token``
    fields for backward compatibility.
    """
    if not body.mode:
        raise HTTPException(status_code=400, detail="mode is required")

    # Convert Pydantic vendor bodies to plain dicts for the command layer.
    vendor_dicts: list[dict[str, object]] | None = None
    if body.vendors:
        vendor_dicts = [
            {
                "vendor": v.vendor,
                "base_url": v.base_url,
                "auth": v.auth.model_dump(),
                "enabled": v.enabled,
            }
            for v in body.vendors
        ]

    try:
        proxy_commands.set_config(
            mode=body.mode,
            vendors=vendor_dicts,
            base_url=body.base_url,
            api_token=body.api_token,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return _serialize_config(masked=True)


@router.get("/_dev/proxy/recordings")
def list_recordings() -> dict[str, object]:
    """Return all stored recordings, newest first."""
    recordings = proxy_queries.list_recordings()
    return {
        "data": [
            {
                "id": r.id,
                "method": r.method,
                "path": r.path,
                "query_string": r.query_string,
                "response_status": r.response_status,
                "response_content_type": r.response_content_type,
                "recorded_at": r.recorded_at,
                "base_url": r.base_url,
                "vendor": r.vendor,
            }
            for r in recordings
        ],
        "pagination": {"totalItems": len(recordings)},
    }


@router.delete("/_dev/proxy/recordings")
def clear_recordings() -> dict[str, object]:
    """Delete all stored recordings."""
    count = proxy_commands.clear_recordings()
    return {"data": {"cleared": count}}


@router.get("/_dev/proxy/vendors")
def list_vendors() -> dict[str, object]:
    """Return supported vendor keys, labels, and default auth types."""
    labels = proxy_queries.vendor_labels()
    return {
        "data": [
            {"vendor": k, "label": labels[k], "default_auth_type": VENDOR_DEFAULT_AUTH[k]}
            for k in sorted(labels)
        ]
    }
