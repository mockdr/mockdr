"""Elasticsearch REST API router.

Implements core Elasticsearch endpoints (search, get, mapping, stats)
mounted at ``/elastic``.  These are the endpoints that SOAR integrations
use when configured to talk directly to Elasticsearch.
"""
from __future__ import annotations

import json
from fnmatch import fnmatch

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from api.es_auth import require_es_auth, require_es_write
from api.spa import spa_response, wants_html
from application.es_search import queries as search_queries
from application.es_search.queries import IndexNotFoundError, MultipleIndicesError
from utils.es_mapping import MappingConflictError, flatten_properties
from utils.es_query import ESQueryError
from utils.es_response import (
    build_es_error_response,
    build_es_index_not_found,
    build_es_invalid_index_name,
    build_es_resource_exists,
)
from utils.id_gen import new_hex

router = APIRouter(tags=["ES Search"])


def _missing_index(exc: IndexNotFoundError) -> HTTPException:
    """Translate a missing index into Elasticsearch's 404."""
    return HTTPException(status_code=404, detail=build_es_index_not_found(exc.index))


# ── Cluster Info ─────────────────────────────────────────────────────────────


@router.get("/")
def cluster_info(
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return Elasticsearch cluster info."""
    return search_queries.cluster_info()


# ── Cluster / cat APIs ───────────────────────────────────────────────────────


@router.get("/_cluster/health")
@router.get("/_cluster/health/{index}")
def cluster_health(
    index: str = "",
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return cluster health, which most clients probe before anything else."""
    return search_queries.es_cluster_health(index)


@router.get("/_cat/indices")
@router.get("/_cat/indices/{pattern}")
def cat_indices(
    pattern: str = "",
    format: str = Query(default="json"),  # noqa: A002 - ES's own parameter name
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List indices. Only ``format=json`` is served; the text table is not."""
    rows = search_queries.es_cat_indices()
    if pattern and pattern not in ("*", "_all"):
        rows = [r for r in rows if fnmatch(str(r["index"]), pattern)]
    return rows


@router.get("/_cat/health")
def cat_health(
    format: str = Query(default="json"),  # noqa: A002 - ES's own parameter name
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """One-row cluster health, as ``_cat/health?format=json`` returns."""
    health = search_queries.es_cluster_health()
    return [{
        "epoch": "0",
        "timestamp": "00:00:00",
        "cluster": health["cluster_name"],
        "status": health["status"],
        "node.total": str(health["number_of_nodes"]),
        "node.data": str(health["number_of_data_nodes"]),
        "shards": str(health["active_shards"]),
        "pri": str(health["active_primary_shards"]),
        "relo": "0",
        "init": "0",
        "unassign": "0",
        "pending_tasks": "0",
        "max_task_wait_time": "-",
        "active_shards_percent": "100.0%",
    }]


@router.get("/_security/_authenticate")
def authenticate(
    user: dict = Depends(require_es_auth),
) -> dict:
    """Report the authenticated user, which clients use to verify credentials."""
    username = str(user.get("username", "elastic"))
    return {
        "username": username,
        "roles": list(user.get("roles", ["superuser"])),
        "full_name": None,
        "email": None,
        "metadata": {},
        "enabled": True,
        "authentication_realm": {"name": "native", "type": "native"},
        "lookup_realm": {"name": "native", "type": "native"},
        "authentication_type": "realm",
    }


# ── Search ───────────────────────────────────────────────────────────────────


@router.get("/_search", operation_id="es_search_all_get")
@router.post("/_search", operation_id="es_search_all_post")
def es_search_all(
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    source: str | None = Query(default=None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Search across every index, which is what ``/_search`` with no index means.

    This route did not exist, so ``POST /_search`` fell through to the 404
    handler — and a malformed query body never reached the parser at all,
    answering ``resource_not_found_exception`` where Elasticsearch answers
    ``parsing_exception``. Both measured against Elasticsearch 8.15.0.
    """
    return search_queries.es_search(
        "_all", _body_or_source(body, source), ignore_unavailable=ignore_unavailable,
    )


def _body_or_source(body: dict, source: str | None) -> dict:
    """``GET _search?source=…`` carries the body in the query string.

    It was ignored, so a malformed query sent that way answered 200 with
    every hit instead of the parsing_exception Elasticsearch returns.
    """
    if not source:
        return body
    try:
        parsed = json.loads(source)
    except ValueError as exc:
        raise ESQueryError(f"Failed to parse request body: {exc}") from exc
    return parsed if isinstance(parsed, dict) else {}


@router.get("/_count", operation_id="es_count_all_get")
@router.post("/_count", operation_id="es_count_all_post")
def es_count_all(
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Count across every index; the route was missing, like ``/_search`` was."""
    return search_queries.es_count("_all", body, ignore_unavailable=ignore_unavailable)


@router.get("/_mget", operation_id="es_mget_all_get")
@router.post("/_mget", operation_id="es_mget_all_post")
def es_mget_all(
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Fetch documents by ``docs`` entries that each name their own index."""
    if not body.get("docs") and not body.get("ids"):
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception",
            "Validation Failed: 1: no documents to get;",
        ))
    return search_queries.es_mget("_all", body)


@router.post("/_bulk", operation_id="es_bulk")
@router.put("/_bulk", operation_id="es_bulk_put")
async def es_bulk(
    request: Request,
    _: dict = Depends(require_es_write),
) -> dict:
    """Index documents from NDJSON action/source pairs.

    Both refusals measured on 8.15: an empty body is parse_exception
    "request body is required"; a body that is not JSON is
    x_content_parse_exception with Jackson's diagnostic. Valid pairs are
    indexed through the same path as ``PUT /{index}/_doc/{id}``.
    """
    raw = (await request.body()).decode("utf-8", errors="replace")
    lines = [line for line in raw.split("\n") if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "parse_exception", "request body is required",
        ))
    items: list[dict] = []
    i = 0
    while i < len(lines):
        try:
            action = json.loads(lines[i])
        except json.JSONDecodeError as exc:
            detail = _bulk_parse_error(lines[i], exc, i + 1)
            raise HTTPException(status_code=400, detail=detail) from exc
        verb = next(iter(action), "") if isinstance(action, dict) and action else ""
        meta = action.get(verb) if isinstance(action, dict) else None
        if verb not in _BULK_VERBS or not isinstance(meta, dict):
            # Elasticsearch's wording, measured on 8.15 — it names the
            # offending key, or the line's shape when there is no key.
            found = verb or _JSON_TOKEN_OF.get(type(action), "VALUE_STRING")
            raise HTTPException(status_code=400, detail=build_es_error_response(
                400, "illegal_argument_exception",
                f"Malformed action/metadata line [{i + 1}], expected field [create], "
                f"[delete], [index] or [update] but found [{found}]",
            ))
        doc: dict = {}
        if verb in ("index", "create", "update"):
            i += 1
            if i < len(lines):
                try:
                    doc = json.loads(lines[i])
                except json.JSONDecodeError as exc:
                    raise HTTPException(status_code=400, detail=build_es_error_response(
                        400, "x_content_parse_exception", _jackson_message(lines[i], exc, i + 1),
                    )) from exc
        index = str(meta.get("_index") or "")
        doc_id = str(meta.get("_id") or new_hex()[:20])
        source = doc.get("doc", doc) if verb == "update" else doc
        result = search_queries.es_index_doc(index, doc_id, source)
        status = 201 if result.get("result") == "created" else 200
        items.append({verb: {**result, "status": status}})
        i += 1
    return {"errors": False, "took": 1, "items": items}


_BULK_VERBS = frozenset({"create", "delete", "index", "update"})
_JSON_TOKEN_OF = {list: "START_ARRAY", str: "VALUE_STRING", int: "VALUE_NUMBER",
                  float: "VALUE_NUMBER", type(None): "VALUE_NULL", bool: "VALUE_TRUE"}


def _jackson_message(line: str, exc: json.JSONDecodeError, line_no: int) -> str:
    """Elasticsearch relays Jackson's parse error, position and all."""
    col = exc.colno + 1  # Jackson's column is one past the offending character
    ch = line[exc.colno - 1] if 0 < exc.colno <= len(line) else ""
    return (
        f"[{line_no}:{col}] Unexpected character ('{ch}' (code {ord(ch) if ch else 0})): "
        f"was expecting double-quote to start field name\n at [Source: (byte[])\"{line}\"; "
        f"line: {line_no}, column: {col}]"
    )


def _bulk_parse_error(line: str, exc: json.JSONDecodeError, line_no: int) -> dict:
    """The x_content_parse_exception body, with the json_parse_exception it wraps."""
    message = _jackson_message(line, exc, line_no)
    content = build_es_error_response(400, "x_content_parse_exception", message)
    # caused_by carries Jackson's message without the [line:col] prefix (measured).
    content["error"]["caused_by"] = {
        "type": "json_parse_exception", "reason": message.split("] ", 1)[1],
    }
    return content


@router.get("/{index}/_search", operation_id="es_search_get")
@router.post("/{index}/_search", operation_id="es_search_post")
def es_search(
    index: str,
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    source: str | None = Query(default=None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Execute an Elasticsearch query DSL search against a mock index."""
    try:
        return search_queries.es_search(
            index, _body_or_source(body, source), ignore_unavailable=ignore_unavailable,
        )
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_count", operation_id="es_count_get")
@router.post("/{index}/_count", operation_id="es_count_post")
def es_count(
    index: str,
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return a document count without the hits."""
    try:
        return search_queries.es_count(
            index, body, ignore_unavailable=ignore_unavailable,
        )
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_mget", operation_id="es_mget_get")
@router.post("/{index}/_mget", operation_id="es_mget_post")
def es_mget(
    index: str,
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Fetch several documents by id in one request."""
    return search_queries.es_mget(index, body)



# ── Mapping / Stats ──────────────────────────────────────────────────────────


@router.get("/{index}/_mapping")
def get_mapping(
    index: str,
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return the index mapping for a known index pattern."""
    try:
        return search_queries.es_get_mapping(index, ignore_unavailable=ignore_unavailable)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_mapping/field/{field}")
def get_field_mapping(
    index: str,
    field: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """One field's mapping, in the shape ``_mapping/field`` answers with."""
    try:
        mapping = search_queries.es_get_mapping(index)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    entry: dict = next(iter(mapping.values()), {})
    properties = (entry.get("mappings") or {}).get("properties") or {}
    spec = flatten_properties(properties).get(field)
    fields = {} if spec is None else {
        field: {"full_name": field, "mapping": {field: spec}},
    }
    return {index: {"mappings": fields}}


@router.put("/{index}/_mapping", operation_id="es_put_mapping")
def put_mapping(
    index: str,
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Add fields to an index's mapping.

    A cluster takes new fields and refuses a type change, because the
    documents are already indexed under the type they have.
    """
    try:
        return search_queries.put_mapping(index, body)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    except MappingConflictError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "illegal_argument_exception", str(exc),
        )) from exc


@router.get("/{index}/_field_caps", operation_id="es_field_caps_get")
@router.post("/{index}/_field_caps", operation_id="es_field_caps_post")
def field_caps(
    index: str,
    fields: str | None = Query(default=None),
    body: dict | None = Body(default=None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """What each field is and whether it can be searched or aggregated.

    Every Kibana data view asks for this before it can draw anything, and
    mockdr did not serve it at all.
    """
    wanted = [f for f in (fields or "").split(",") if f]
    wanted += [str(f) for f in (body or {}).get("fields", [])]
    try:
        return search_queries.es_field_caps(index, wanted)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_stats")
def get_stats(
    index: str,
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return index stats for a known index pattern."""
    try:
        return search_queries.es_get_stats(index, ignore_unavailable=ignore_unavailable)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


# ── Document CRUD ────────────────────────────────────────────────────────────


@router.get("/{index}/_doc/{doc_id}")
def get_doc(
    index: str,
    doc_id: str,
    response: Response,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single document by ID.

    A miss is a ``404`` carrying ``found: false`` — not the standard error
    envelope, and not the ``200`` this returned before. Elasticsearch's own
    REST spec test asserts the 404; its API reference documents only the 200,
    which is why the status is easy to get wrong.
    """
    try:
        result = search_queries.es_get_doc(index, doc_id)
    except MultipleIndicesError as exc:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(400, "illegal_argument_exception", str(exc)),
        ) from exc
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc

    if result is None:
        response.status_code = 404
        return {"_index": index, "_id": doc_id, "found": False}
    return result


@router.post("/{index}/_doc/{doc_id}", operation_id="es_index_doc_post")
@router.put("/{index}/_doc/{doc_id}", operation_id="es_index_doc_put")
def index_doc(
    index: str,
    doc_id: str,
    body: dict = Body(...),
    refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> JSONResponse:
    """Index (create or replace) a document.

    The document is stored and searchable, so a subsequent ``GET _doc`` and a
    subsequent search both find it. This used to answer ``result: created``
    without writing anything, which meant the very next read 404'd.
    """
    forced = _forced_refresh(refresh)
    result = search_queries.es_index_doc(index, doc_id, body)
    if forced:
        result["forced_refresh"] = True
    # 201 the first time, 200 for a replacement — which is how a client tells
    # a create from an update without reading the body.
    created = result.get("result") == "created"
    return JSONResponse(status_code=201 if created else 200, content=result)


def _forced_refresh(refresh: str | None) -> bool:
    """Read the ``refresh`` parameter, refusing a value Elasticsearch refuses."""
    try:
        return search_queries.refresh_forced(refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "illegal_argument_exception", str(exc),
        )) from exc


@router.put("/{index}", operation_id="es_create_index")
def create_index(
    index: str,
    body: dict | None = Body(default=None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create an index, so a client can search what it then writes to it."""
    if index.startswith("_"):
        raise HTTPException(status_code=400, detail=build_es_invalid_index_name(index))
    try:
        return search_queries.create_index(
            index, (body or {}).get("settings"), (body or {}).get("mappings"),
        )
    except search_queries.IndexExistsError as exc:
        raise HTTPException(status_code=400, detail=build_es_resource_exists(
            exc.index, exc.uuid,
        )) from exc


@router.get("/{index}", operation_id="es_get_index")
async def get_index(request: Request, index: str) -> Response:
    """The index's settings and mappings.

    `HEAD /{index}` — how every client asks whether an index exists — is
    served from this by the HEAD middleware, so both answer 200 or 404
    together, as they do on a real cluster.

    The UI routes under this prefix too (``/elastic/rules`` is a page), so a
    browser navigation gets the SPA and only an API client gets the index.
    Authentication is checked after that, for the same reason: a navigation
    must not be answered with the API's 401.
    """
    if wants_html(request):
        # A UI navigation, whether or not the frontend is built: answering it
        # with the API's 401 would put an auth prompt in front of a page.
        navigation = spa_response(request)
        if navigation is not None:
            return navigation
        raise HTTPException(status_code=404, detail=build_es_index_not_found(index))
    await require_es_auth(request, request.headers.get("authorization", ""))
    if index.startswith("_"):
        raise HTTPException(status_code=400, detail=build_es_invalid_index_name(index))
    described = search_queries.describe_index(index)
    if described is None:
        raise HTTPException(
            status_code=404, detail=build_es_index_not_found(index),
        )
    return JSONResponse(content=described)


@router.delete("/{index}", operation_id="es_delete_index")
def delete_index(index: str, _: dict = Depends(require_es_write)) -> dict:
    """Delete an index and everything written to it."""
    if index.startswith("_"):
        raise HTTPException(status_code=400, detail=build_es_invalid_index_name(index))
    result = search_queries.delete_index(index)
    if result is None:
        raise HTTPException(
            status_code=404, detail=build_es_index_not_found(index),
        )
    return result


@router.delete("/{index}/_doc/{doc_id}")
def delete_doc(
    index: str,
    doc_id: str,
    refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete a document written through the index API."""
    forced = _forced_refresh(refresh)
    result = search_queries.es_delete_doc(index, doc_id)
    if result is not None and forced:
        result["forced_refresh"] = True
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"_index": index, "_id": doc_id, "result": "not_found"},
        )
    return result
