"""Splunk authentication router.

Handles login, current-context, user listing, roles, and capabilities.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request

from api.splunk_auth import require_splunk_auth
from application.splunk.commands.auth import login
from application.splunk.queries.users import (
    get_current_context,
    get_user,
    list_capabilities,
    list_roles,
    list_users,
)

router = APIRouter(tags=["Splunk Auth"])


@router.post("/services/auth/login")
async def auth_login(
    request: Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
    output_mode: str = Form(default="json"),
) -> dict:
    """Authenticate and return a session key.

    Accepts form-encoded ``username`` and ``password``.
    """
    # Also accept JSON body
    if not username:
        try:
            body = await request.json()
            username = body.get("username", "")
            password = body.get("password", "")
        except Exception:
            pass

    if not username or not password:
        raise HTTPException(status_code=401, detail={"messages": [
            {"type": "WARN", "text": "Login failed"},
        ]})

    result = login(username, password)
    if not result:
        raise HTTPException(status_code=401, detail={"messages": [
            {"type": "WARN", "text": "Login failed"},
        ]})
    return result


@router.get("/services/authentication/current-context")
def get_current_user_context(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Return the current authenticated user context."""
    return get_current_context(current_user["username"])


@router.get("/services/authentication/users")
def list_all_users(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all Splunk users."""
    return list_users()


@router.get("/services/authentication/users/{name}")
def get_single_user(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a specific user by username."""
    result = get_user(name)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"User '{name}' not found"},
        ]})
    return result


@router.get("/services/authorization/roles")
def list_all_roles(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all Splunk roles."""
    return list_roles()


@router.get("/services/authorization/capabilities")
def list_all_capabilities(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all Splunk capabilities."""
    return list_capabilities()
