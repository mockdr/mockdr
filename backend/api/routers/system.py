from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from application.system import commands as system_commands
from application.system import queries as system_queries
from utils.s1_fixtures import restrict_s1
from utils.vendor_errors import build_vendor_error

public_router = APIRouter(tags=["System"])
router = APIRouter(tags=["System"])


@public_router.get("/system/status")
def system_status() -> dict:
    """Return the health status of the mock server (unauthenticated)."""
    return {"data": {"health": "ok"}}


@router.get("/system/info")
def system_info() -> dict:
    """Return mock server version and latest agent version information."""
    # system_SystemInfoSchema: build/patch/release/version, not the invented
    # serverVersion/buildTime this used to answer.
    return restrict_s1(
        {
            "data": {
                "version": "23.1.2",
                "build": "183",
                "patch": "2",
                "release": "23.1",
                "latestAgentVersion": "23.4.2.3",
            }
        },
        "system_SystemInfoSchema_200",
    )


@router.get("/system/configuration")
def system_configuration() -> dict:
    """Return this console's configuration.

    The settings a client has set are answered back; the rest are completed
    to the schema. It used to answer three invented keys the schema does not
    declare, which the completion dropped — so the console reported settings
    nothing could ever change.
    """
    return restrict_s1(
        {"data": system_queries.get_configuration()},
        "system_SystemConfigurationSchema_200",
    )


@router.put("/system/configuration")
def set_system_configuration(body: dict, _: dict = Depends(require_admin)) -> dict:
    """Change this console's configuration.

    The 2.1 API answers the configuration that resulted, so the next GET and
    this reply agree.
    """
    try:
        settings = system_commands.update_configuration(body)
    except system_commands.InvalidConfigurationError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc
    return restrict_s1({"data": settings}, "system_SystemConfigurationSchema_200")
