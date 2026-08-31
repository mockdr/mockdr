"""Splunk KV Store router."""
from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.reserved_names import register as _register_convertors
from api.splunk_auth import require_splunk_admin, require_splunk_auth
from application.splunk.commands.kvstore import (
    DuplicateKeyError,
    batch_save,
    create_collection,
    delete_all_records,
    delete_collection,
    delete_record,
    insert_record,
    update_record,
)
from application.splunk.queries.kvstore import (
    collection_exists,
    get_collection_config,
    get_record,
    get_records,
    list_collections,
)
from utils.splunk.response import build_splunk_entry, build_splunk_envelope, build_splunk_error

_register_convertors()

router = APIRouter(tags=["Splunk KV Store"])


# ── Collection config ──────────────────────────────────────────────────────

#: splunkd serves the KV Store's *configuration* only under the `nobody`
#: user context: `/servicesNS/admin/search/storage/collections/config` and
#: the bare `/services/...` form are both refused with this, measured on
#: 10.4.2. The data routes beside them are not restricted that way.
_COLLECTION_CONTEXT = (
    "Must use user context of 'nobody' when interacting with collection "
    "configurations (used user='{user}')"
)


def _require_nobody(owner: str, current_user: dict) -> None:
    """Refuse a collection-configuration call outside the `nobody` context.

    Raises:
        HTTPException: 400, as splunkd answers it.
    """
    if owner == "nobody":
        return
    raise HTTPException(
        status_code=400,
        detail=build_splunk_error(
            400, _COLLECTION_CONTEXT.format(user=owner or current_user.get("username", "")),
        ),
    )


@router.get("/services/storage/collections/config")
def list_all_kv_collections(
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Refuse the app-less form, as splunkd does.

    The bare path resolves to the calling user's own context, and the KV
    Store's configuration is served only under `nobody` — mockdr answered
    every collection to anyone who asked here.
    """
    _require_nobody("", current_user)
    return list_collections(None)


@router.get("/servicesNS/{owner}/{app}/storage/collections/config")
def list_kv_collections(
    owner: str,
    app: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """List KV Store collections, under the one context that may."""
    _require_nobody(owner, current_user)
    return list_collections(app)


@router.get("/servicesNS/{owner}/{app}/storage/collections/config/{name}")
def get_kv_collection(
    owner: str,
    app: str,
    name: str,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """One KV Store collection's configuration, which nothing here served."""
    _require_nobody(owner, current_user)
    found = get_collection_config(name, app)
    if found is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Could not find object id={name}"},
        ]})
    return found


@router.post("/servicesNS/{owner}/{app}/storage/collections/config")
async def create_kv_collection(
    owner: str,
    app: str,
    request: Request,
    output_mode: str = "json",
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Create a KV Store collection."""
    body = await _parse_body(request)
    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR",
             "text": 'Cannot perform action "POST" without a target name to act on.'},
        ]})
    coll = create_collection(name, app, owner)
    return {"name": coll.name}


@router.delete("/servicesNS/{owner}/{app}/storage/collections/config/{name}")
def delete_kv_collection(
    owner: str,
    app: str,
    name: str,
    current_user: dict = Depends(require_splunk_admin),
) -> dict:
    """Delete a KV Store collection."""
    if not delete_collection(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return {"messages": [{"type": "INFO", "text": f"Collection '{name}' deleted"}]}


# ── Collection data ────────────────────────────────────────────────────────

@router.get("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
def get_all_records(
    owner: str,
    app: str,
    name: str,
    query: str = Query(default=""),
    fields: str = Query(default=""),
    sort: str = Query(default=""),
    limit: int = Query(default=0),
    skip: int = Query(default=0),
    current_user: dict = Depends(require_splunk_auth),
) -> list[dict]:
    """Get records from a KV collection.

    ``query``, ``fields``, ``sort``, ``limit`` and ``skip`` are all documented
    on this endpoint and are what splunklib's ``query()`` sends; none were
    declared here, so every one was dropped and the whole collection came back.
    """
    if not collection_exists(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return get_records(
        name, app, query=query, fields=fields, sort=sort, limit=limit, skip=skip,
    )


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
async def insert_kv_record(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Insert a record into a KV collection.

    Real Splunk answers 201 with only the new document key, and rejects a
    duplicate ``_key`` with 409 — this used to return 200 with the whole
    record and append a second copy under the same key.
    """
    body = await request.json()
    try:
        result = insert_record(name, body, app)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail={"messages": [
            {"type": "ERROR", "text": str(exc)},
        ]}) from exc
    if not result:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return JSONResponse(status_code=201, content={"_key": result["_key"]})


# splunkd routes both verbs here — its 405 for a third one names
# `Allow: POST,PUT` (measured on 10.4.2), and mockdr served only
# the one, so a client using the other met a refusal that does not
# exist.
@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}/batch_save")
@router.put("/servicesNS/{owner}/{app}/storage/collections/data/{name}/batch_save")
async def batch_save_records(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> list[str]:
    """Batch upsert records into a KV collection.

    splunkd answers with the keys it wrote — ``["a", "b"]``, bare strings —
    and this answered a list of ``{"_key": …}`` objects, which is close
    enough to read as right and is not what a client indexes into.
    """
    records = await request.json()
    # Each element too, not just the array. `batch_find` beside this guards
    # its elements; this one handed a string to `record.get("_key")` and
    # answered 500 where its sibling answers 400.
    if not isinstance(records, list) or any(
        not isinstance(record, dict) for record in records
    ):
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Expected a JSON array of records"},
        ]})
    return batch_save(name, records, app)


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}/batch_find")
@router.put("/servicesNS/{owner}/{app}/storage/collections/data/{name}/batch_find")
async def batch_find_records(
    owner: str,
    app: str,
    name: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> list[list[dict]]:
    """Run several KV Store queries in one request.

    splunklib's ``KVStoreCollectionData.batch_find`` posts an array and reads
    back one result array per element. Each element is a *wrapper* —
    ``{"query": {...}}`` — and mockdr read the element itself as the filter,
    so the documented form matched a field called `query` that no record has
    and came back empty, while an undocumented bare filter worked.

    An element with no ``query`` matches everything, which is what splunkd
    does rather than erroring; an element that is not an object is the one
    thing it refuses (all measured on 10.4.2).
    """
    if not collection_exists(name, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})

    queries = await request.json()
    if not isinstance(queries, list):
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "ERROR", "text": "Expected a JSON array of query objects"},
        ]})

    for element in queries:
        if not isinstance(element, dict):
            raise HTTPException(status_code=400, detail={"messages": [
                {"type": "ERROR", "text": "The provided query was invalid."},
            ]})
    return [
        get_records(
            name, app,
            query=json.dumps(element["query"])
            if isinstance(element.get("query"), dict) else "",
        )
        for element in queries
    ]


@router.get("/servicesNS/{owner}/{app}/storage/collections/data/{name}/{key:kvkey}")
def get_kv_record(
    owner: str,
    app: str,
    name: str,
    key: str,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Get a single record from a KV collection."""
    result = get_record(name, key, app)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Record '{key}' not found"},
        ]})
    return result


@router.post("/servicesNS/{owner}/{app}/storage/collections/data/{name}/{key:kvkey}")
async def update_kv_record(
    owner: str,
    app: str,
    name: str,
    key: str,
    request: Request,
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Update a record in a KV collection."""
    body = await request.json()
    result = update_record(name, key, body, app)
    if result is None:
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Record '{key}' not found"},
        ]})
    return result


@router.delete("/servicesNS/{owner}/{app}/storage/collections/data/{name}/{key:kvkey}")
def delete_kv_record(
    owner: str,
    app: str,
    name: str,
    key: str,
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Delete a record from a KV collection."""
    if not delete_record(name, key, app):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"Record '{key}' not found"},
        ]})
    return JSONResponse(status_code=200, content={})


@router.delete("/servicesNS/{owner}/{app}/storage/collections/data/{name}")
def delete_all_kv_records(
    owner: str,
    app: str,
    name: str,
    query: str = Query(default=""),
    current_user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Delete all records from a KV collection."""
    if not delete_all_records(name, app, query):
        raise HTTPException(status_code=404, detail={"messages": [
            {"type": "ERROR", "text": f"An object with name={name} does not exist"},
        ]})
    return JSONResponse(status_code=200, content={})


async def _parse_body(request: Request) -> dict:
    """Parse request body from form or JSON."""
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        return {k: str(v) for k, v in form.items()}
    try:
        parsed = await request.json()
    except Exception:
        return {}
    # A JSON `null` or array is not a parameter set; treating it as an empty
    # one lets the route report the parameter it needed, instead of 500.
    return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}


# ── Status ───────────────────────────────────────────────────────────────────
#
# What a client checks before it trusts the KV store with anything — and what
# the conformance harness itself waits for on a real instance. mockdr
# answered 404, so a client that checks first concluded there was no KV store
# and went no further.

@router.get("/services/kvstore/status")
def kvstore_status(_user: dict = Depends(require_splunk_auth)) -> dict:
    """Report the KV store as ready, in the shape splunkd reports it.

    A single member — mockdr is one instance, so it is its own captain — and
    a `current` block a client reads `status` out of. The oplog timestamps
    and the guid are this instance's own; the fields around them are the
    ones splunkd fills (measured on 10.4.2).
    """
    started = int(_STARTED)
    now = int(time.time())
    current = {
        "backupRestoreStatus": "Ready",
        "date": 0,
        "dateSec": float(now),
        "disabled": False,
        "guid": KVSTORE_GUID,
        "migrationStatus": "NotStarted",
        "oplogEndTimestamp": 0,
        "oplogEndTimestampSec": now,
        "oplogStartTimestamp": 0,
        "oplogStartTimestampSec": started,
        "port": 8191,
        "replicaSet": "splunkrs",
        "replicationStatus": "KV store captain",
        "standalone": True,
        "status": "ready",
        "storageEngine": "wiredTiger",
        "versionUpgradeInProgress": "0",
    }
    member = {
        "configVersion": 1,
        "electionDate": 0,
        "electionDateSec": started,
        "hostAndPort": "127.0.0.1:8191",
        "lastHeartbeat": None,
        "lastHeartbeatRecv": None,
        "lastHeartbeatRecvSec": None,
        "lastHeartbeatSec": None,
        "optimeDate": 0,
        "optimeDateSec": now,
        "pingMs": None,
        "replicationStatus": "KV store captain",
        "uptime": now - started,
    }
    entry = build_splunk_entry(
        "status",
        {"current": current, "members": {"0": member}, "eai:acl": None},
        collection="kvstore/status",
        links=("alternate", "list"),
        fields=False,
    )
    # The status collection offers no links of its own: nothing to create
    # and nothing to reload.
    return {
        **build_splunk_envelope([entry], origin="/services/kvstore/status"),
        "links": {},
    }


#: When this instance's KV store came up, so `uptime` grows the way a real
#: one's does rather than being a constant.
_STARTED = time.time()

#: The identity this KV store answers with. A real one's is per install; a
#: client that stores it and compares later needs it to stay put.
KVSTORE_GUID = "6D8C4A2E-0F31-4A6B-9C77-1B2E5A9D3F44"
