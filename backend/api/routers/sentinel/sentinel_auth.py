"""Sentinel OAuth2 authentication router."""
from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException

from application.sentinel.commands.auth import token_exchange

router = APIRouter(tags=["Sentinel Auth"])


@router.post("/oauth2/v2.0/token")
async def oauth2_token(
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
    grant_type: str = Form(default=""),
) -> dict:
    """Exchange client credentials for an access token."""
    result = token_exchange(client_id, client_secret)
    if not result:
        raise HTTPException(status_code=401, detail={
            "error": "invalid_client",
            "error_description": "Invalid client credentials",
        })
    return result
