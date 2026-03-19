"""Router for tag-manager CRUD endpoints."""
from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from api.dto.requests import TagCreateBody, TagUpdateBody
from application.tags import commands as tag_commands

router = APIRouter(tags=["Tag Manager"])


@router.post("/tag-manager")
def create_tag(body: TagCreateBody, current_user: dict = Depends(require_admin)) -> dict:
    """Create a new scoped tag definition."""
    user_name = current_user.get("fullName") or current_user.get("email", "")
    user_id = current_user.get("userId", "")
    return tag_commands.create_tag(body.model_dump(), user_name, user_id)


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
