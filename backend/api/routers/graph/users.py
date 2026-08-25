"""Microsoft Graph Users endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.graph_auth import require_graph_auth
from application.graph.users import queries as user_queries
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Users"])


@router.get("/v1.0/me")
async def get_me(
    select: str = Query(None, alias="$select"),
    current_client: dict = Depends(require_graph_auth),
) -> dict:
    """Reject ``/me`` the way Graph does under app-only authentication.

    ``/me`` resolves the signed-in user, and the client-credentials flow this
    mock implements has none. Real Graph answers 400; returning some user
    instead would let an integration ship a call that cannot work in
    production.

    Raises:
        HTTPException: 400 always — there is no delegated user to resolve.
    """
    raise HTTPException(400, detail=build_graph_error_response(
        "Request_BadRequest",
        "/me request is only valid with delegated authentication flow.",
    ))


@router.get("/v1.0/users")
async def list_users(
    request: Request,
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    search: str = Query(None, alias="$search"),
    count: bool = Query(False, alias="$count"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List users with OData query parameters."""
    consistency_level = request.headers.get("consistencylevel")
    return user_queries.list_users(
        filter_str, top, skip, orderby, select, search, count,
        consistency_level,
    )


@router.get("/beta/users")
async def list_users_beta(
    request: Request,
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    search: str = Query(None, alias="$search"),
    count: bool = Query(False, alias="$count"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List users (beta) — includes signInActivity by default."""
    consistency_level = request.headers.get("consistencylevel")
    return user_queries.list_users(
        filter_str, top, skip, orderby, select, search, count,
        consistency_level,
    )


@router.get("/v1.0/users/{user_id}")
async def get_user(
    user_id: str,
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get a single user by ID or userPrincipalName."""
    result = user_queries.get_user(user_id, select=select)
    if result is None:
        from fastapi import HTTPException

        from utils.graph_response import build_graph_error_response
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "Request_ResourceNotFound",
                f"User '{user_id}' not found",
            ),
        )
    return result


@router.get("/v1.0/users/{user_id}/memberOf")
async def list_user_member_of(
    user_id: str,
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List groups and directory roles a user is a member of."""
    return user_queries.get_user_member_of(
        user_id, filter_str=filter_str, top=top, skip=skip, select=select,
    )


@router.get("/v1.0/users/{user_id}/mailFolders/inbox/messageRules")
async def list_user_mail_rules(
    user_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List inbox message rules for a user."""
    return user_queries.get_user_mail_rules(user_id)
