"""Splunk HEC token management router (data inputs)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from api.splunk_auth import require_splunk_auth
from domain.splunk.hec_token import HecToken
from repository.splunk.hec_token_repo import hec_token_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope

router = APIRouter(tags=["Splunk Inputs"])


@router.get("/servicesNS/{owner}/splunk_httpinput/data/inputs/http")
def list_hec_tokens(
    owner: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List HEC tokens."""
    tokens = hec_token_repo.list_all()
    entries = []
    for t in tokens:
        content = {
            "token": t.token,
            "index": t.index,
            "indexes": t.indexes,
            "sourcetype": t.sourcetype,
            "source": t.source,
            "host": t.host,
            "disabled": t.disabled,
            "useACK": t.use_ack,
        }
        entries.append(build_splunk_entry(t.name, content))
    return build_splunk_envelope(entries)


@router.post("/servicesNS/{owner}/splunk_httpinput/data/inputs/http")
async def create_hec_token(
    owner: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Create a new HEC token."""
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        body: dict = {k: str(v) for k, v in form.items()}
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}

    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Token name is required"},
        ]})

    token = HecToken(
        name=name,
        token=str(uuid.uuid4()),
        index=body.get("index", "main"),
        sourcetype=body.get("sourcetype", ""),
    )
    hec_token_repo.save(token)
    content = {"token": token.token, "index": token.index, "name": token.name}
    return build_splunk_envelope([build_splunk_entry(name, content)], total=1)


@router.delete("/servicesNS/{owner}/splunk_httpinput/data/inputs/http/{name}")
def delete_hec_token(
    owner: str,
    name: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Delete an HEC token by name."""
    token = hec_token_repo.get_by_name(name)
    if not token:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"HEC token '{name}' not found"},
        ]})
    hec_token_repo.delete(token.token)
    return {"messages": [{"type": "INFO", "text": f"HEC token '{name}' deleted"}]}
