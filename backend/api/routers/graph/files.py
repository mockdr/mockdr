"""Microsoft Graph Files (OneDrive / SharePoint) endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.graph_auth import require_graph_auth
from application.graph.files import queries as files_queries

router = APIRouter(tags=["Graph Files"])


@router.get("/v1.0/users/{user_id}/drive")
async def get_user_drive(
    user_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get the user's OneDrive."""
    result = files_queries.get_user_drive(user_id=user_id)
    if result is None:
        from fastapi import HTTPException

        from utils.graph_response import build_graph_error_response
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "NotFound",
                f"Drive not found for user '{user_id}'",
            ),
        )
    return result


@router.get("/v1.0/users/{user_id}/drive/root/children")
async def list_drive_root_children(
    user_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List root-level items in a user's OneDrive."""
    drive = files_queries.get_user_drive(user_id=user_id)
    if drive is None:
        from fastapi import HTTPException

        from utils.graph_response import build_graph_error_response
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "NotFound",
                f"Drive not found for user '{user_id}'",
            ),
        )
    return files_queries.list_drive_children(drive_id=drive["id"], item_id="root")


@router.get("/v1.0/sites")
async def list_sites(
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List SharePoint sites."""
    return files_queries.list_sites()
