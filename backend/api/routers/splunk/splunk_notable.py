"""Splunk Enterprise Security notable events router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.dto.splunk.requests import NotableUpdateRequest
from api.splunk_auth import require_splunk_auth
from application.splunk.commands.notable import update_notable

router = APIRouter(tags=["Splunk Notable Events"])


@router.post("/services/notable_update")
async def notable_update(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Update notable event(s).

    Used by XSOAR ``splunk-notable-update`` command.
    Accepts form-encoded or JSON body.
    """
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        params: dict = {}
        for k, v in form.items():
            params[k] = str(v)
        # ruleUIDs comes as semicolon-separated in form
        rule_uids_str = params.get("ruleUIDs", "")
        if rule_uids_str:
            params["ruleUIDs"] = [uid.strip() for uid in rule_uids_str.split(";") if uid.strip()]
    else:
        try:
            raw = await request.json()
            dto = NotableUpdateRequest(**raw)
            params = dto.model_dump()
        except Exception:
            params = {}

    rule_uids = params.get("ruleUIDs", [])
    if isinstance(rule_uids, str):
        rule_uids = [uid.strip() for uid in rule_uids.split(";") if uid.strip()]

    return update_notable(
        ruleUIDs=rule_uids,
        newUrgency=params.get("newUrgency", ""),
        status=params.get("status", ""),
        newOwner=params.get("newOwner", ""),
        comment=params.get("comment", ""),
    )
