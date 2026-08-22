from fastapi import APIRouter

from utils.s1_fixtures import restrict_s1

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
    """Return mock system configuration settings."""
    # system_SystemConfigurationSchema declares the real settings; the three
    # invented keys this used to answer are dropped.
    return restrict_s1(
        {
            "data": {
                "enforcementMode": "protect",
                "maxFreeSpaceForLog": 2048,
                "logLevel": "info",
            }
        },
        "system_SystemConfigurationSchema_200",
    )
