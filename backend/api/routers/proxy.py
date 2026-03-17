"""Recording proxy management endpoints.

GET    /_dev/proxy/config       — get current proxy mode and settings
POST   /_dev/proxy/config       — set mode, base_url, api_token
GET    /_dev/proxy/recordings   — list all recorded exchanges
DELETE /_dev/proxy/recordings   — clear all recordings
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from api.dto.requests import ProxyConfigBody
from application.proxy import commands as proxy_commands
from application.proxy import queries as proxy_queries

router = APIRouter(tags=["Proxy"])


@router.get("/_dev/proxy/config")
def get_proxy_config() -> dict[str, object]:
    """Return current proxy configuration (api_token is masked)."""
    cfg = proxy_queries.get_config()
    return {
        "data": {
            "mode": cfg.mode,
            "base_url": cfg.base_url,
            "api_token": cfg.api_token,  # already masked by get_config()
            "recording_count": proxy_queries.recording_count(),
        }
    }


@router.post("/_dev/proxy/config")
def set_proxy_config(body: ProxyConfigBody, _: dict = Depends(require_admin)) -> dict[str, object]:
    """Update proxy mode and optionally the upstream connection settings.

    Args:
        body: Dict with ``mode`` (required), optional ``base_url`` and ``api_token``.

    Returns:
        Dict with ``data`` containing the updated config.

    Raises:
        HTTPException: 400 if ``mode`` is not ``off``, ``record``, or ``replay``.
    """
    if not body.mode:
        raise HTTPException(status_code=400, detail="mode is required")
    try:
        cfg = proxy_commands.set_config(
            mode=body.mode,
            base_url=body.base_url,
            api_token=body.api_token,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "data": {
            "mode": cfg.mode,
            "base_url": cfg.base_url,
            "api_token": proxy_queries.get_config().api_token,  # masked
            "recording_count": proxy_queries.recording_count(),
        }
    }


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
            }
            for r in recordings
        ],
        "pagination": {"totalItems": len(recordings)},
    }


@router.delete("/_dev/proxy/recordings")
def clear_recordings() -> dict[str, object]:
    """Delete all stored recordings.

    Returns:
        Dict with ``data.cleared`` indicating how many were removed.
    """
    count = proxy_commands.clear_recordings()
    return {"data": {"cleared": count}}
