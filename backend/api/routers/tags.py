"""Router for tag-manager CRUD endpoints."""
from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from api.dto.requests import TagCreateBody, TagUpdateBody
from application.tags import commands as tag_commands
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Tag Manager"])


@router.post("/tag-manager")
def create_tag(body: TagCreateBody, current_user: dict = Depends(require_admin)) -> dict:
    """Create a new scoped tag definition."""
    user_name = current_user.get("fullName") or current_user.get("email", "")
    user_id = current_user.get("userId", "")
    try:
        return tag_commands.create_tag(body.model_dump(), user_name, user_id)
    except tag_commands.InvalidTagError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc


@router.delete("/tag-manager")
def delete_tags_by_filter(body: dict, _: dict = Depends(require_admin)) -> dict:
    """Delete the tag definitions the body's ``filter`` selects.

    The 2.1 API deletes by filter here; mockdr served only the by-id path
    and answered 405 to the call the vendor documents.
    """
    try:
        return tag_commands.delete_tags(body.get("filter") or {})
    except tag_commands.UnfilterableError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc


@router.put("/tag-manager/{tag_id}")
def update_tag(
    tag_id: str, body: TagUpdateBody, current_user: dict = Depends(require_admin),
) -> dict:
    """Update a tag definition's key, value, or description."""
    user_name = current_user.get("fullName") or current_user.get("email", "")
    user_id = current_user.get("userId", "")
    result = tag_commands.update_tag(tag_id, body.model_dump(), user_name, user_id)
    if result is None:
        raise HTTPException(status_code=404)
    return result


@router.delete("/tag-manager/{tag_id}")
def delete_tag(tag_id: str, _: dict = Depends(require_admin)) -> dict:
    """Delete a tag definition and remove all agent assignments."""
    return tag_commands.delete_tag(tag_id)
