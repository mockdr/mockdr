"""Microsoft Graph Mail endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from api.graph_auth import require_graph_auth
from application.graph.mail import queries as mail_queries

router = APIRouter(tags=["Graph Mail"])


@router.get("/v1.0/users/{user_id}/messages")
async def list_messages(
    user_id: str,
    top: int = Query(25, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List mail messages for a user (inbox by default)."""
    return mail_queries.list_messages(user_id=user_id, top=top, skip=skip)


@router.get("/v1.0/users/{user_id}/messages/{message_id}")
async def get_message(
    user_id: str,
    message_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get a single mail message."""
    result = mail_queries.get_message(user_id=user_id, message_id=message_id)
    if result is None:
        from fastapi import HTTPException

        from utils.graph_response import build_graph_error_response
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "NotFound",
                f"Message '{message_id}' not found",
            ),
        )
    return result


@router.post("/v1.0/users/{user_id}/sendMail")
async def send_mail(
    user_id: str,
    request: Request,
    _: dict = Depends(require_graph_auth),
) -> JSONResponse:
    """Send a mail message (returns 202 Accepted)."""
    body = await request.json()
    mail_queries.send_mail(user_id=user_id, body=body)
    return JSONResponse(status_code=202, content=None)


@router.get("/v1.0/users/{user_id}/mailFolders")
async def list_mail_folders(
    user_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List mail folders for a user."""
    return mail_queries.list_mail_folders(user_id=user_id)
