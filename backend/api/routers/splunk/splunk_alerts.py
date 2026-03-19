"""Splunk fired alerts router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.splunk_auth import require_splunk_auth
from repository.store import store
from utils.splunk.response import build_splunk_envelope

router = APIRouter(tags=["Splunk Alerts"])

_COLLECTION = "splunk_fired_alerts"


@router.get("/services/alerts/fired_alerts")
def list_fired_alerts(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List fired alerts."""
    from utils.splunk.response import build_splunk_entry
    alerts = store.get_all(_COLLECTION)
    entries = [build_splunk_entry(a.get("name", ""), a) for a in alerts]
    return build_splunk_envelope(entries)


@router.get("/services/alerts/fired_alerts/{name}")
def get_fired_alert(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a specific fired alert."""
    for a in store.get_all(_COLLECTION):
        if a.get("name") == name:
            from utils.splunk.response import build_splunk_entry
            return build_splunk_envelope([build_splunk_entry(name, a)], total=1)
    raise HTTPException(status_code=404, detail={"messages": [
        {"type": "ERROR", "text": f"Fired alert '{name}' not found"},
    ]})


@router.delete("/services/alerts/fired_alerts/{name}")
def delete_fired_alert(
    name: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Delete a fired alert."""
    for a in store.get_all(_COLLECTION):
        if a.get("name") == name:
            store.delete(_COLLECTION, a.get("_id", ""))
            return {"messages": [{"type": "INFO", "text": f"Fired alert '{name}' deleted"}]}
    raise HTTPException(status_code=404, detail={"messages": [
        {"type": "ERROR", "text": f"Fired alert '{name}' not found"},
    ]})
