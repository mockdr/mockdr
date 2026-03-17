from fastapi import APIRouter

public_router = APIRouter(tags=["System"])
router = APIRouter(tags=["System"])


@public_router.get("/system/status")
def system_status() -> dict:
    """Return the health status of the mock server (unauthenticated)."""
    return {"data": {"health": "ok"}}


@router.get("/system/info")
def system_info() -> dict:
    """Return mock server version and latest agent version information."""
    return {"data": {
        "serverVersion": "23.1.2.183",
        "latestAgentVersion": "23.4.2.3",
        "buildTime": "2024-01-15T10:00:00Z",
    }}


@router.get("/system/configuration")
def system_configuration() -> dict:
    """Return mock system configuration settings."""
    return {"data": {
        "enforcementMode": "protect",
        "maxFreeSpaceForLog": 2048,
        "logLevel": "info",
    }}
