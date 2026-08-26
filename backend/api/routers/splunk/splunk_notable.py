"""Splunk Enterprise Security notable events router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.splunk_auth import require_splunk_ingest
from application.splunk.commands.notable import update_notable

router = APIRouter(tags=["Splunk Notable Events"])


@router.post("/services/notable_update")
async def notable_update(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_ingest),
) -> dict:
    """Update notable event(s).

    Used by XSOAR ``splunk-notable-update`` command.
    Accepts form-encoded or JSON body.

    Enterprise Security gates this on the ``edit_notable_events`` capability,
    which its analyst and admin roles hold and the plain ``user`` role does
    not — so a read-only account changing a notable's status and owner, which
    mockdr allowed, is something no ES would let it do.
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
        # Validating the JSON body against a DTO of `str` fields and falling
        # back to `{}` meant one field of the wrong type discarded the whole
        # request: `{"ruleUIDs": [...], "status": 3}` — a status code, which
        # is a number — was answered `success: false, No event IDs provided`,
        # while `status=3` form-encoded on this same route went through. The
        # body is read the way the form is read instead: scalars as the
        # strings splunkd receives, `ruleUIDs` as the list it is.
        params = _json_params(await _raw_json(request))

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


async def _raw_json(request: Request) -> object:
    """The JSON body, or `None` when there is none to read."""
    try:
        return await request.json()
    except ValueError:
        return None


def _json_params(raw: object) -> dict:
    """A JSON body as the parameter set the form path would have produced."""
    if not isinstance(raw, dict):
        return {}
    params: dict = {}
    for key, value in raw.items():
        # A form carries strings and repeated keys, and nothing else.
        params[key] = [str(item) for item in value] if isinstance(value, list) else str(value)
    return params
