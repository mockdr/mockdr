"""Splunk indexes router."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_splunk_admin, require_splunk_auth
from application.splunk.queries.indexes import (
    actioned_index,
    created_index,
    get_index,
    list_indexes,
)
from domain.splunk.splunk_index import SplunkIndex
from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.response import complete

router = APIRouter(tags=["Splunk Indexes"])


@router.get("/services/data/indexes")
def list_all_indexes(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List all indexes."""
    return list_indexes()


#: The argument names splunkd's index handler accepts, recorded from
#: ``GET /services/data/indexes/_new`` on Splunk 10.4.2. Anything else is
#: refused by name — splunkd does not ignore an argument it does not know.
_INDEX_ARGUMENTS: frozenset[str] = frozenset(
    json.loads(
        (Path(__file__).resolve().parents[3]
         / "infrastructure" / "fixtures" / "splunk" / "indexes_new_arguments.json")
        .read_text(),
    )["arguments"],
)


#: splunkd's REST framework reads these wherever they appear, body included,
#: so they are not the index handler's to refuse.
_FRAMEWORK_ARGS = frozenset({"output_mode", "count", "offset", "f", "add_orphan_field"})


async def _index_arguments(request: Request) -> dict[str, str]:
    """The settings a request carries, refusing any name splunkd would."""
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        sent = {k: str(v) for k, v in (await request.form()).items()}
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}
        sent = {k: str(v) for k, v in body.items()} if isinstance(body, dict) else {}
    for argument in sent:
        if argument in _FRAMEWORK_ARGS:
            continue
        if argument not in _INDEX_ARGUMENTS:
            raise HTTPException(status_code=400, detail={"messages": [
                {"type": "ERROR",
                 "text": f'Argument "{argument}" is not supported by this handler.'},
            ]})
    return sent


def _typed(settings: dict[str, str]) -> dict[str, object]:
    """Coerce each setting to the type the recorded index content carries.

    splunkd answers ``maxTotalDataSizeMB`` as a number and ``maxHotBuckets``
    as a string; the recorded entry in ``fixtures/splunk/indexes.json`` holds
    which is which, so a value read back keeps the type it would have had.
    """
    recorded = complete({}, "indexes")
    out: dict[str, object] = {}
    for key, value in settings.items():
        was = recorded.get(key)
        if isinstance(was, bool):
            out[key] = value.strip().lower() in ("1", "true", "t", "yes", "on")
        elif isinstance(was, int):
            try:
                out[key] = int(value)
            except ValueError:
                out[key] = value
        else:
            out[key] = value
    return out


@router.post("/services/data/indexes", response_model=None)
async def create_index(
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> JSONResponse:
    """Create a new index, keeping every setting the request carries."""
    settings = {k: v for k, v in (await _index_arguments(request)).items()
                if k not in _FRAMEWORK_ARGS}
    name = settings.pop("name", "")

    if not name:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR",
             "text": 'Cannot perform action "POST" without a target name to act on.'},
        ]})

    if get_index(name):
        # Splunk refuses a duplicate name rather than silently replacing the
        # existing index and its event count.
        raise HTTPException(status_code=409, detail={"messages": [
            {"type": "ERROR", "text": f"Index '{name}' already exists"},
        ]})

    idx = SplunkIndex(name=name, settings=_typed(settings))
    splunk_index_repo.save(idx)
    return JSONResponse(status_code=201, content=created_index(name))


@router.post("/services/data/indexes/{name}", response_model=None)
async def edit_index(
    name: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Change the settings of an existing index.

    splunkd edits a collection member by POSTing to its own URL. The route
    was absent, so every edit answered 405 and a client had no way to change
    an index it had just made.
    """
    idx = splunk_index_repo.get(name)
    if not idx:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    settings = {k: v for k, v in (await _index_arguments(request)).items()
                if k not in _FRAMEWORK_ARGS}
    settings.pop("name", None)
    idx.settings = {**idx.settings, **_typed(settings)}
    splunk_index_repo.save(idx)
    return get_index(name) or {}


@router.post("/services/data/indexes/{name}/{action}", response_model=None)
def set_index_state(
    name: str,
    action: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Disable or enable an index.

    An index is not disabled by editing a `disabled` argument — the handler
    refuses that name — but through the link the entry itself offers. mockdr
    published those links and answered 404 at the end of them.
    """
    if action not in ("disable", "enable"):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={action}"},
        ]})
    idx = splunk_index_repo.get(name)
    if not idx:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    idx.disabled = action == "disable"
    idx.settings = {k: v for k, v in idx.settings.items() if k != "disabled"}
    splunk_index_repo.save(idx)
    return actioned_index(name)


@router.delete("/services/data/indexes/{name}")
def delete_index(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Delete an index.

    Real Splunk supports this; the route was absent, so DELETE returned 405.
    """
    if not get_index(name):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    splunk_index_repo.delete(name)
    # splunkd answers a delete with the collection as it now stands, not with
    # a message about what went: a client refreshing its list needs no second
    # request.
    return list_indexes()


@router.get("/services/data/indexes/{name}")
def get_single_index(
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a specific index."""
    result = get_index(name)
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    return result
