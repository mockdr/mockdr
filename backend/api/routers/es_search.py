"""Elasticsearch REST API router.

Implements core Elasticsearch endpoints (search, get, mapping, stats)
mounted at ``/elastic``.  These are the endpoints that SOAR integrations
use when configured to talk directly to Elasticsearch.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from fnmatch import fnmatch

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from api.es_auth import require_es_auth, require_es_write
from api.spa import spa_response, wants_html
from application.es_search import queries as search_queries
from application.es_search.queries import IndexNotFoundError, MultipleIndicesError
from utils.es_mapping import MappingConflictError, flatten_properties
from utils.es_painless import PainlessError
from utils.es_query import ESQueryError
from utils.es_response import (
    build_es_document_missing,
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
    format: str = Query(default=""),  # noqa: A002 - ES's own parameter name
    v: bool = Query(default=False),
    h: str = Query(default=""),
    _: dict = Depends(require_es_auth),
) -> Response:
    """List indices, as a text table unless the caller asks for json."""
    rows = search_queries.es_cat_indices()
    if pattern and pattern not in ("*", "_all"):
        rows = [r for r in rows if fnmatch(str(r["index"]), pattern)]
    return _cat_response(rows, format, headers=v, columns=h)


@router.get("/_cat/health")
def cat_health(
    format: str = Query(default=""),  # noqa: A002 - ES's own parameter name
    v: bool = Query(default=False),
    h: str = Query(default=""),
    _: dict = Depends(require_es_auth),
) -> Response:
    """One-row cluster health, as a text table unless json is asked for."""
    health = search_queries.es_cluster_health()
    rows = [{
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
    return _cat_response(rows, format, headers=v, columns=h)


def _cat_response(
    rows: list[dict], format: str, *, headers: bool, columns: str,  # noqa: A002
) -> Response:
    """A `_cat` answer, as json or as the text table that is its default.

    Every `_cat` endpoint answers a *table* unless the caller asks for json,
    and mockdr answered json regardless — so a script reading columns got a
    document. The columns are padded to their widest value, `v` adds the
    header row and `h` picks the columns (all measured against 8.15).
    """
    if format.lower() == "json":
        return JSONResponse(content=rows)
    names = [c.strip() for c in columns.split(",") if c.strip()] or (
        list(rows[0]) if rows else []
    )
    table = [[str(row.get(name, "")) for name in names] for row in rows]
    if headers:
        table.insert(0, names)
    widths = [max((len(cell[i]) for cell in table), default=0) for i in range(len(names))]
    lines = [
        " ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=False)).rstrip()
        for row in table
    ]
    text = "".join(f"{line}\n" for line in lines)
    return Response(content=text, media_type="text/plain; charset=UTF-8")


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
    request: Request,
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

    A body carrying a ``pit`` is addressed to a point in time instead: the
    index is the one it was opened on, and the answer names it back.
    """
    search_body = _with_uri_params(_body_or_source(body, source), request.query_params)
    pit = search_body.get("pit")
    if isinstance(pit, dict):
        return _search_in_pit(str(pit.get("id", "")), search_body)
    return search_queries.es_search(
        "_all", search_body, ignore_unavailable=ignore_unavailable,
    )


def _search_in_pit(pit_id: str, body: dict) -> dict:
    """A search addressed to a point in time rather than to an index."""
    index = search_queries.context_index(pit_id) if pit_id else None
    if index is None:
        raise HTTPException(status_code=404, detail=build_es_error_response(
            404, "search_context_missing_exception",
            f"No search context found for id [{pit_id}]",
        ))
    # A point-in-time search sorts by `_shard_doc` after whatever the client
    # asked for, so every hit has a unique sort value to page from. Without
    # it a `search_after` carrying the tiebreaker back is one value too long
    # for the sort, and the next page is refused.
    sort = [*(body.get("sort") or []), {"_shard_doc": "asc"}]
    search_body = {k: v for k, v in body.items() if k != "pit"}
    page = search_queries.es_search(index, {**search_body, "sort": sort})
    return {**page, "pit_id": pit_id}


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


#: The URI-search parameters, and what each becomes in the body. This is the
#: form a client reaches for from a shell — ``_search?q=name:beta&size=5`` —
#: and mockdr read none of them: the whole index came back, unfiltered,
#: unsorted and unlimited, with a 200. Measured against Elasticsearch 8.15,
#: including that the *URI* wins over the body when both name `size`.
_URI_SEARCH_PARAMS = frozenset({
    "q", "size", "from", "sort", "_source", "_source_includes",
    "_source_excludes", "track_total_hits", "terminate_after", "default_operator",
    "df", "analyzer", "lenient",
})


def _with_uri_params(body: dict, query: Mapping[str, str]) -> dict:
    """Fold the URI-search parameters into the body they stand for."""
    given = {k: v for k, v in query.items() if k in _URI_SEARCH_PARAMS}
    if not given:
        return body
    merged = dict(body)

    if "q" in given:
        options = {
            key: given[key] for key in ("default_operator", "df", "analyzer", "lenient")
            if key in given
        }
        merged["query"] = {"query_string": {"query": given["q"], **options}}
    for name in ("size", "from", "terminate_after"):
        if name in given:
            try:
                merged[name] = int(given[name])
            except ValueError as exc:
                raise ESQueryError(
                    f"Failed to parse int parameter [{name}] with value "
                    f"[{given[name]}]",
                ) from exc
    if "sort" in given:
        merged["sort"] = [
            {field: {"order": order}} if order else field
            for field, _, order in (part.partition(":")
                                    for part in given["sort"].split(",") if part)
        ]
    if "track_total_hits" in given:
        merged["track_total_hits"] = given["track_total_hits"].lower() not in (
            "false", "0", "no")
    includes = given.get("_source_includes")
    excludes = given.get("_source_excludes")
    raw_source = given.get("_source")
    if raw_source is not None and raw_source.lower() in ("true", "false"):
        merged["_source"] = raw_source.lower() == "true"
    elif raw_source:
        includes = raw_source if includes is None else includes
    if includes is not None or excludes is not None:
        projection: dict[str, list[str]] = {}
        if includes:
            projection["includes"] = [f for f in includes.split(",") if f]
        if excludes:
            projection["excludes"] = [f for f in excludes.split(",") if f]
        merged["_source"] = projection
    return merged


@router.get("/_count", operation_id="es_count_all_get")
@router.post("/_count", operation_id="es_count_all_post")
def es_count_all(
    request: Request,
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Count across every index; the route was missing, like ``/_search`` was."""
    return search_queries.es_count(
        "_all", _with_uri_params(body, request.query_params),
        ignore_unavailable=ignore_unavailable,
    )


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
    request: Request,
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    source: str | None = Query(default=None),
    scroll: str | None = Query(default=None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Execute an Elasticsearch query DSL search against a mock index."""
    search_body = _with_uri_params(_body_or_source(body, source), request.query_params)
    try:
        page = search_queries.es_search(
            index, search_body, ignore_unavailable=ignore_unavailable,
        )
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    if scroll:
        # A scrolled search hands back the id the client pages with; without
        # it a fetch that works against a cluster stops after one page here.
        page["_scroll_id"] = search_queries.open_context(index, search_body, "scroll")
    return page


@router.post("/{index}/_pit", operation_id="es_open_pit")
def open_pit(
    index: str,
    _keep_alive: str | None = Query(default=None, alias="keep_alive"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Open a point in time over an index."""
    if not search_queries.index_exists(index) and not search_queries.indices_for_alias(index):
        raise _missing_index(IndexNotFoundError(index))
    return {"id": search_queries.open_context(index, {}, "pit")}


@router.delete("/_pit", operation_id="es_close_pit")
def close_pit(body: dict = Body(...), _: dict = Depends(require_es_auth)) -> dict:
    """Close a point in time."""
    return search_queries.close_context(str(body.get("id", "")))


@router.post("/_search/scroll", operation_id="es_scroll")
@router.get("/_search/scroll", operation_id="es_scroll_get")
def scroll_search(body: dict = Body(default={}), _: dict = Depends(require_es_auth)) -> dict:
    """The next page of a scrolled search."""
    try:
        return search_queries.scroll(str(body.get("scroll_id", "")))
    except search_queries.SearchContextMissingError as exc:
        cause = {"type": "search_context_missing_exception", "reason": str(exc)}
        raise HTTPException(status_code=404, detail={"error": {
            "root_cause": [dict(cause)],
            "type": "search_phase_execution_exception",
            "reason": "all shards failed",
            "phase": "query",
            "grouped": True,
            "failed_shards": [{"shard": -1, "index": None, "reason": dict(cause)}],
            "caused_by": dict(cause),
        }, "status": 404}) from exc


@router.delete("/_search/scroll", operation_id="es_clear_scroll")
def clear_scroll(body: dict = Body(default={}), _: dict = Depends(require_es_auth)) -> dict:
    """Free a scroll the client is done with."""
    return search_queries.close_context(str(body.get("scroll_id", "")))


@router.get("/{index}/_count", operation_id="es_count_get")
@router.post("/{index}/_count", operation_id="es_count_post")
def es_count(
    index: str,
    request: Request,
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return a document count without the hits."""
    try:
        return search_queries.es_count(
            index, _with_uri_params(body, request.query_params),
            ignore_unavailable=ignore_unavailable,
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


@router.post("/{index}/_update/{doc_id}", operation_id="es_update_doc")
def update_doc(
    index: str,
    doc_id: str,
    body: dict = Body(...),
    refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> JSONResponse:
    """Apply a partial document or a script to one document."""
    forced = _forced_refresh(refresh)
    try:
        result = search_queries.es_update_doc(index, doc_id, body)
    except search_queries.DocumentMissingError as exc:
        raise HTTPException(status_code=404, detail=build_es_document_missing(
            exc.index, search_queries.es_index_uuid(exc.index), exc.doc_id,
        )) from exc
    except PainlessError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "illegal_argument_exception", str(exc),
        )) from exc
    if forced and result["result"] != "noop":
        result["forced_refresh"] = True
    created = result.get("result") == "created"
    return JSONResponse(status_code=201 if created else 200, content=result)


@router.post("/{index}/_update_by_query", operation_id="es_update_by_query")
def update_by_query(
    index: str,
    request: Request,
    body: dict | None = Body(default=None),
    _refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Apply a script to every document a query matches."""
    try:
        return search_queries.es_update_by_query(
            index, _with_uri_params(body or {}, request.query_params))
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    except PainlessError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "illegal_argument_exception", str(exc),
        )) from exc


@router.post("/{index}/_delete_by_query", operation_id="es_delete_by_query")
def delete_by_query(
    index: str,
    request: Request,
    body: dict | None = Body(default=None),
    _refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete every document a query matches.

    ``q`` in the query string narrows what is deleted, and reading it was
    not optional: ``_delete_by_query?q=name:zzz`` emptied the index here and
    deleted nothing on a cluster.
    """
    try:
        return search_queries.es_delete_by_query(
            index, _with_uri_params(body or {}, request.query_params))
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_source/{doc_id}", operation_id="es_get_source")
def get_source(
    index: str,
    doc_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """A document's ``_source`` alone, which is what most clients want."""
    try:
        source = search_queries.es_get_source(index, doc_id)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    if source is None:
        raise HTTPException(status_code=404, detail=build_es_error_response(
            404, "resource_not_found_exception",
            f"Document not found [{index}]/[{doc_id}]",
        ))
    return source


#: The maintenance calls a client makes around a write. mockdr holds its
#: documents in memory, so each is a no-op — but answering 404 made an
#: ingest script that refreshes after writing look like it had failed.
_SHARD_ACK = {"_shards": {"total": 2, "successful": 1, "failed": 0}}


@router.post("/{index}/_refresh", operation_id="es_refresh")
@router.post("/{index}/_flush", operation_id="es_flush")
@router.post("/{index}/_forcemerge", operation_id="es_forcemerge")
@router.post("/{index}/_cache/clear", operation_id="es_cache_clear")
def refresh_index(index: str, _: dict = Depends(require_es_auth)) -> dict:
    """Answer the maintenance calls that follow a write."""
    try:
        search_queries.es_get_stats(index)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    return dict(_SHARD_ACK)


@router.post("/_msearch", operation_id="es_msearch_all")
@router.post("/{index}/_msearch", operation_id="es_msearch")
async def msearch(request: Request, index: str = "", _: dict = Depends(require_es_auth)) -> dict:
    """Several searches in one request, the way Kibana asks for them.

    The body is NDJSON: a header line naming the index, then the search body,
    twice over. Each answer carries the search's own ``status`` beside it, so
    one failing search does not fail the request.
    """
    lines = [line for line in (await request.body()).decode().split("\n") if line.strip()]
    responses: list[dict] = []
    for i in range(0, len(lines) - 1, 2):
        try:
            header = json.loads(lines[i])
            body = json.loads(lines[i + 1])
        except json.JSONDecodeError as exc:
            raise ESQueryError(f"Failed to parse request body: {exc}") from exc
        target = str(header.get("index") or index or "_all")
        try:
            responses.append(_one_search(target, body))
        except ESQueryError as exc:
            # The position belongs to this line, which is the search the
            # client wrote — not to its offset in the payload.
            exc.body = lines[i + 1]
            raise
    return {"took": 1, "responses": responses}


def _one_search(index: str, body: dict) -> dict:
    """One member of a multi-search: its answer, or its error, plus a status.

    Only what a *shard* raises belongs to the member — a missing index, a
    field it cannot sort on. A body that will not **parse** fails the whole
    request instead, which is what a cluster does: the error is in the
    request, not in one of the searches (measured on 8.15).
    """
    try:
        return {**search_queries.es_search(index, body), "status": 200}
    except IndexNotFoundError as exc:
        return {**build_es_index_not_found(exc.index), "status": 404}
    except ESQueryError as exc:
        if not exc.shard_failure:
            raise
        return {
            **build_es_error_response(400, exc.es_type, str(exc)),
            "status": 400,
        }


@router.get("/{index}/_settings", operation_id="es_get_settings")
def get_settings(index: str, _: dict = Depends(require_es_auth)) -> dict:
    """An index's settings, which is the half of it a client tunes."""
    try:
        return search_queries.index_settings(index)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.put("/{index}/_settings", operation_id="es_put_settings")
def put_settings(
    index: str, body: dict = Body(...), _: dict = Depends(require_es_write),
) -> dict:
    """Change an index's settings."""
    try:
        return search_queries.put_settings(index, body)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.put("/{index}/_alias/{alias}", operation_id="es_put_alias")
def put_alias(index: str, alias: str, _: dict = Depends(require_es_write)) -> dict:
    """Point an alias at an index."""
    try:
        return search_queries.put_alias(index, alias)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.delete("/{index}/_alias/{alias}", operation_id="es_delete_alias")
def delete_alias(index: str, alias: str, _: dict = Depends(require_es_write)) -> dict:
    """Take an alias off an index."""
    try:
        return search_queries.delete_alias(index, alias)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index}/_alias", operation_id="es_get_index_alias")
def get_index_alias(index: str, _: dict = Depends(require_es_auth)) -> dict:
    """Which aliases an index carries."""
    if not search_queries.index_exists(index):
        raise _missing_index(IndexNotFoundError(index))
    return search_queries.alias_map(index)


@router.post("/_aliases", operation_id="es_update_aliases")
def update_aliases(body: dict = Body(...), _: dict = Depends(require_es_write)) -> dict:
    """Add and remove aliases in one request."""
    try:
        return search_queries.update_aliases(body.get("actions") or [])
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/_alias/{alias}", operation_id="es_get_alias")
def get_alias(alias: str, _: dict = Depends(require_es_auth)) -> dict:
    """Every index an alias stands for."""
    found = search_queries.alias_map(alias)
    if not found:
        # A plain string, where every other Elasticsearch error is an object:
        # this one endpoint answers `{"error": "alias [x] missing"}`.
        raise HTTPException(
            status_code=404,
            detail={"error": f"alias [{alias}] missing", "status": 404},
        )
    return found


@router.get("/_resolve/index/{expression}", operation_id="es_resolve_index")
def resolve_index(expression: str, _: dict = Depends(require_es_auth)) -> dict:
    """What a name stands for: indices, aliases and data streams."""
    return search_queries.resolve_index(expression)


@router.post("/{index}/_analyze", operation_id="es_analyze")
def analyze(
    index: str, body: dict = Body(default={}), _: dict = Depends(require_es_auth),
) -> dict:
    """The tokens a field's analyser would make of some text."""
    try:
        return search_queries.analyze_text(index, body)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception", str(exc),
        )) from exc


@router.post("/{index}/_validate/query", operation_id="es_validate_query")
def validate_query(
    index: str,
    body: dict = Body(default={}),
    explain: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Whether a query would run, without running it."""
    try:
        return search_queries.validate_query(index, body, explain=explain)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception", str(exc),
        )) from exc


@router.post("/{index}/_terms_enum", operation_id="es_terms_enum")
def terms_enum(
    index: str, body: dict = Body(default={}), _: dict = Depends(require_es_auth),
) -> dict:
    """The values of a field, which is what an autocomplete asks for."""
    try:
        return search_queries.terms_enum(index, body)
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
        # Elasticsearch answers a delete that found nothing with the *document*
        # envelope, not an error one — the same seven members a successful
        # delete carries, with `result: "not_found"` (measured on 8.15). The
        # mock sent three of the seven, so a client reading `_seq_no` or
        # `_shards` from a delete reply — which is what optimistic concurrency
        # does — found them missing on exactly the path where it matters.
        raise HTTPException(
            status_code=404,
            detail={
                "_index": index, "_id": doc_id, "_version": 1,
                "result": "not_found",
                "_shards": {"total": 2, "successful": 1, "failed": 0},
                "_seq_no": 0, "_primary_term": 1,
            },
        )
    return result
