"""Elasticsearch REST API router.

Implements core Elasticsearch endpoints (search, get, mapping, stats)
mounted at ``/elastic``.  These are the endpoints that SOAR integrations
use when configured to talk directly to Elasticsearch.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from fnmatch import fnmatch

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from api.es_auth import require_es_auth, require_es_write
from api.reserved_names import register as _register_convertors
from api.spa import spa_response, wants_html
from application.es_search import queries as search_queries
from application.es_search.queries import IndexNotFoundError, MultipleIndicesError
from utils.es_mapping import MappingConflictError, flatten_properties
from utils.es_painless import PainlessError
from utils.es_params import refuses_unknown as es_refuses_unknown
from utils.es_query import ESQueryError
from utils.es_response import (
    build_es_document_missing,
    build_es_error_response,
    build_es_index_not_found,
    build_es_invalid_index_name,
    build_es_resource_exists,
)
from utils.id_gen import new_hex

_register_convertors()

router = APIRouter(tags=["ES Search"])

#: What each of these routes accepts, measured one parameter at a time on
#: 8.15 against the cluster's own oracle: it calls an unrecognised parameter
#: unrecognised and complains about the *value* of a known one, so the two
#: are told apart by the message and not by the status. `format`,
#: `ignore_throttled` and the index-selection options reach further than the
#: documentation suggests, and asking every route about every candidate is
#: the only way that showed — a shorter candidate list invented a 400 on
#: `_stats?ignore_unavailable=`, which this repo's own tests caught.
_SEARCH_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "allow_no_indices",
    "allow_partial_search_results", "analyze_wildcard", "analyzer",
    "batched_reduce_size", "ccs_minimize_roundtrips", "default_operator", "df",
    "docvalue_fields", "expand_wildcards", "explain", "force_synthetic_source",
    "from", "ignore_throttled", "ignore_unavailable", "include_named_queries_score",
    "index", "lenient", "max_concurrent_shard_requests",
    "min_compatible_shard_node", "pre_filter_shard_size", "preference", "q",
    "request_cache", "rest_total_hits_as_int", "routing", "scroll", "search_type",
    "seq_no_primary_term", "size", "sort", "stats", "stored_fields",
    "suggest_field", "suggest_mode", "suggest_size", "suggest_text",
    "terminate_after", "timeout", "track_scores", "track_total_hits", "typed_keys",
    "version",
)
_COUNT_PARAMS = (
    "allow_no_indices", "analyze_wildcard", "analyzer", "default_operator", "df",
    "expand_wildcards", "ignore_throttled", "ignore_unavailable", "index",
    "lenient", "min_score", "preference", "q", "routing", "terminate_after",
)
#: The index form takes exactly the same members as the cluster-wide one.
_CLUSTER_HEALTH_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "index", "level", "local", "master_timeout", "timeout",
    "wait_for_active_shards", "wait_for_events", "wait_for_no_initializing_shards",
    "wait_for_no_relocating_shards", "wait_for_nodes", "wait_for_status",
)
_CAT_INDICES_PARAMS = (
    "allow_no_indices", "bytes", "expand_wildcards", "h", "health", "help",
    "ignore_throttled", "ignore_unavailable", "include_unloaded_segments", "index",
    "local", "master_timeout", "pri", "s", "size", "time", "ts", "v",
)
_CAT_HEALTH_PARAMS = (
    "bytes", "h", "help", "pri", "s", "size", "time", "ts", "v",
)
_SCROLL_PARAMS = ("rest_total_hits_as_int", "scroll", "scroll_id")
#: `/_alias/{alias}` and `/{index}/_alias` take the same members.
_ALIAS_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "index", "local", "name",
)
_RESOLVE_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "name",
)
_INDEX_PARAMS = (
    "allow_no_indices", "expand_wildcards", "features", "flat_settings",
    "ignore_throttled", "ignore_unavailable", "include_defaults", "index", "local",
    "master_timeout",
)
_FIELD_CAPS_PARAMS = (
    "allow_no_indices", "expand_wildcards", "fields", "filters", "ignore_throttled",
    "ignore_unavailable", "include_empty_fields", "include_unmapped", "index",
    "types",
)
_MAPPING_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "index", "local", "master_timeout",
)
_FIELD_MAPPING_PARAMS = (
    "allow_no_indices", "expand_wildcards", "fields", "ignore_throttled",
    "ignore_unavailable", "include_defaults", "index",
)
_SETTINGS_PARAMS = (
    "allow_no_indices", "expand_wildcards", "flat_settings", "ignore_throttled",
    "ignore_unavailable", "include_defaults", "index", "local", "master_timeout",
    "name",
)
_STATS_PARAMS = (
    "allow_no_indices", "completion_fields", "expand_wildcards", "fielddata_fields",
    "fields", "forbid_closed_indices", "groups", "ignore_throttled",
    "ignore_unavailable", "include_segment_file_sizes", "include_unloaded_segments",
    "index", "level", "metric",
)
_DOC_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "fields",
    "force_synthetic_source", "index", "preference", "realtime", "refresh",
    "routing", "stored_fields", "version", "version_type",
)
_DOC_SOURCE_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "index", "preference",
    "realtime", "refresh", "routing",
)

#: What the routes that *write* accept. Measured the same way and just as
#: safely: a cluster refuses an unrecognised parameter before it acts, so a
#: `DELETE` carrying one leaves the document where it was — which is what
#: mockdr did not do, and why a client with a typo could delete data here
#: that a real cluster would have refused to touch.
_SEARCH_POST_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "allow_no_indices",
    "allow_partial_search_results", "analyze_wildcard", "analyzer",
    "batched_reduce_size", "ccs_minimize_roundtrips", "default_operator", "df",
    "docvalue_fields", "expand_wildcards", "explain", "force_synthetic_source",
    "from", "ignore_throttled", "ignore_unavailable", "include_named_queries_score",
    "index", "lenient", "max_concurrent_shard_requests",
    "min_compatible_shard_node", "pre_filter_shard_size", "preference", "q",
    "request_cache", "rest_total_hits_as_int", "routing", "scroll", "search_type",
    "seq_no_primary_term", "size", "sort", "stats", "stored_fields",
    "suggest_field", "suggest_mode", "suggest_size", "suggest_text",
    "terminate_after", "timeout", "track_scores", "track_total_hits", "typed_keys",
    "version",
)
_COUNT_POST_PARAMS = (
    "allow_no_indices", "analyze_wildcard", "analyzer", "default_operator", "df",
    "expand_wildcards", "ignore_throttled", "ignore_unavailable", "index",
    "lenient", "min_score", "preference", "q", "routing", "terminate_after",
)
_CACHE_CLEAR_PARAMS = (
    "allow_no_indices", "expand_wildcards", "fields", "ignore_throttled",
    "ignore_unavailable", "index",
)
_FIELD_CAPS_POST_PARAMS = (
    "allow_no_indices", "expand_wildcards", "fields", "filters", "ignore_throttled",
    "ignore_unavailable", "include_empty_fields", "include_unmapped", "index",
    "types",
)
_FLUSH_PARAMS = (
    "allow_no_indices", "expand_wildcards", "force", "ignore_throttled",
    "ignore_unavailable", "index", "wait_if_ongoing",
)
_FORCEMERGE_PARAMS = (
    "allow_no_indices", "expand_wildcards", "flush", "ignore_throttled",
    "ignore_unavailable", "index", "max_num_segments", "only_expunge_deletes",
    "wait_for_completion",
)
_PIT_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "index", "keep_alive", "max_concurrent_shard_requests",
    "preference", "routing",
)
_REFRESH_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "index",
)
_VALIDATE_QUERY_PARAMS = (
    "all_shards", "allow_no_indices", "expand_wildcards", "explain",
    "ignore_throttled", "ignore_unavailable", "index", "q", "rewrite",
)
_UPDATE_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "if_primary_term",
    "if_seq_no", "index", "refresh", "retry_on_conflict", "routing", "timeout",
    "version", "version_type", "wait_for_active_shards",
)
_UPDATE_BY_QUERY_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "allow_no_indices",
    "allow_partial_search_results", "analyze_wildcard", "analyzer",
    "batched_reduce_size", "ccs_minimize_roundtrips", "conflicts",
    "default_operator", "df", "docvalue_fields", "expand_wildcards", "explain",
    "force_synthetic_source", "from", "ignore_throttled", "ignore_unavailable",
    "include_named_queries_score", "index", "lenient",
    "max_concurrent_shard_requests", "max_docs", "pipeline",
    "pre_filter_shard_size", "preference", "q", "refresh", "request_cache",
    "requests_per_second", "rest_total_hits_as_int", "routing", "scroll",
    "scroll_size", "search_type", "seq_no_primary_term", "size", "slices", "sort",
    "stats", "stored_fields", "suggest_field", "suggest_mode", "suggest_size",
    "suggest_text", "terminate_after", "timeout", "track_scores",
    "track_total_hits", "version", "wait_for_active_shards", "wait_for_completion",
)
_DELETE_BY_QUERY_PARAMS = (
    "_source", "_source_excludes", "_source_includes", "allow_no_indices",
    "allow_partial_search_results", "analyze_wildcard", "analyzer",
    "batched_reduce_size", "ccs_minimize_roundtrips", "conflicts",
    "default_operator", "df", "docvalue_fields", "expand_wildcards", "explain",
    "force_synthetic_source", "from", "ignore_throttled", "ignore_unavailable",
    "include_named_queries_score", "index", "lenient",
    "max_concurrent_shard_requests", "max_docs", "pre_filter_shard_size",
    "preference", "q", "refresh", "request_cache", "requests_per_second",
    "rest_total_hits_as_int", "routing", "scroll", "scroll_size", "search_type",
    "seq_no_primary_term", "size", "slices", "sort", "stats", "stored_fields",
    "suggest_field", "suggest_mode", "suggest_size", "suggest_text",
    "terminate_after", "timeout", "track_scores", "track_total_hits", "version",
    "wait_for_active_shards", "wait_for_completion",
)
_PUT_INDEX_PARAMS = (
    "index", "master_timeout", "timeout", "wait_for_active_shards",
)
_ALIAS_WRITE_PARAMS = (
    "index", "master_timeout", "name", "timeout",
)
_SCROLL_DELETE_PARAMS = ("scroll_id",)
_DOC_DELETE_PARAMS = (
    "if_primary_term", "if_seq_no", "index", "refresh", "routing", "timeout",
    "version", "version_type", "wait_for_active_shards",
)
_DELETE_INDEX_PARAMS = (
    "allow_no_indices", "expand_wildcards", "ignore_throttled",
    "ignore_unavailable", "index", "master_timeout", "timeout",
)


def _missing_index(exc: IndexNotFoundError) -> HTTPException:
    """Translate a missing index into Elasticsearch's 404."""
    return HTTPException(status_code=404, detail=build_es_index_not_found(exc.index))


# ── Cluster Info ─────────────────────────────────────────────────────────────


@router.get("/", dependencies=[es_refuses_unknown(source=False)])
def cluster_info(
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return Elasticsearch cluster info."""
    return search_queries.cluster_info()


# ── Cluster / cat APIs ───────────────────────────────────────────────────────


@router.get(
    "/_cluster/health",
    dependencies=[es_refuses_unknown(*_CLUSTER_HEALTH_PARAMS, source=False)],
)
@router.get(
    "/_cluster/health/{index}",
    dependencies=[es_refuses_unknown(*_CLUSTER_HEALTH_PARAMS, source=False)],
)
def cluster_health(
    index: str = "",
    _: dict = Depends(require_es_auth),
) -> dict:
    """Return cluster health, which most clients probe before anything else."""
    return search_queries.es_cluster_health(index)


@router.get(
    "/_cat/indices",
    dependencies=[es_refuses_unknown(*_CAT_INDICES_PARAMS, source=False)],
)
@router.get(
    "/_cat/indices/{pattern}",
    dependencies=[es_refuses_unknown(*_CAT_INDICES_PARAMS, source=False)],
)
def cat_indices(
    pattern: str = "",
    format: str = Query(default=""),  # noqa: A002 - ES's own parameter name
    v: str | None = Query(default=None),
    h: str = Query(default=""),
    s: str = Query(default=""),
    bytes: str = Query(default=""),  # noqa: A002 - ES's own parameter name
    _: dict = Depends(require_es_auth),
) -> Response:
    """List indices, as a text table unless the caller asks for json."""
    rows = search_queries.es_cat_indices()
    if pattern and pattern not in ("*", "_all"):
        rows = [r for r in rows if fnmatch(str(r["index"]), pattern)]
    return _cat_response(
        rows, format, headers=_flag(v), columns=h, order=s, byte_unit=bytes,
    )


@router.get(
    "/_cat/health",
    dependencies=[es_refuses_unknown(
        *_CAT_HEALTH_PARAMS, source=False,
    )],
)
def cat_health(
    format: str = Query(default=""),  # noqa: A002 - ES's own parameter name
    v: str | None = Query(default=None),
    h: str = Query(default=""),
    s: str = Query(default=""),
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
    return _cat_response(rows, format, headers=_flag(v), columns=h, order=s)


class CatSortError(ValueError):
    """A `_cat` sort naming a column no row carries."""


def _flag(value: str | None) -> bool:
    """A `_cat` flag, which is true when named at all.

    `?v` — no value — is the canonical way to ask for a header row, and
    declaring it as a boolean made FastAPI refuse the empty value with a
    400. `?v=false` is still false.
    """
    if value is None:
        return False
    return value.strip().lower() not in ("false", "0", "no")


def _cat_sorted(rows: list[dict], order: str) -> list[dict]:
    """Order the rows per `s=column[:asc|desc]`, as Elasticsearch does.

    A column no row carries is a 400 there, and was silently ignored here.
    """
    for clause in reversed([c.strip() for c in order.split(",") if c.strip()]):
        column, _, direction = clause.partition(":")
        if rows and column not in rows[0]:
            # Elasticsearch's own wording, and its own exception type: this
            # is an illegal argument, not a parse failure (measured on 8.15).
            raise CatSortError(f"Unable to sort by unknown sort key `{column}`")
        rows = sorted(
            rows, key=lambda row: _cat_key(row.get(column)),
            reverse=direction.lower() == "desc",
        )
    return rows


def _cat_key(value: object) -> tuple[int, float, str]:
    text = "" if value is None else str(value)
    try:
        return (0, float(text), "")
    except ValueError:
        return (1, 0.0, text)


#: The `_cat` columns whose value is a number of bytes, and which the
#: `bytes` parameter therefore chooses the unit for.
_BYTE_COLUMNS = frozenset({"store.size", "dataset.size", "pri.store.size"})

#: What each `bytes` value divides by. No value at all means the
#: human-readable form: `249b`, `77.6kb` (measured on 8.15).
_BYTE_UNITS = {
    "b": 1, "k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2,
    "g": 1024**3, "gb": 1024**3, "t": 1024**4, "tb": 1024**4,
}


def _bytes_as(value: object, unit: str) -> str:
    """One byte count, in the unit the caller asked for.

    Without `bytes`, Elasticsearch writes the human form it writes
    everywhere — one decimal, lower-case unit, 1024 to the step. With it,
    the count is divided and truncated, so `bytes=mb` on 77 kB is `0`.
    """
    if not isinstance(value, int):
        return str(value)
    if unit:
        return str(value // _BYTE_UNITS.get(unit.lower(), 1))
    size = float(value)
    for suffix in ("b", "kb", "mb", "gb", "tb"):
        if size < 1024 or suffix == "tb":
            if suffix == "b":
                return f"{int(size)}b"
            return _one_decimal(size) + suffix
        size /= 1024
    return _one_decimal(size) + "tb"


def _one_decimal(size: float) -> str:
    """One decimal at most, truncated — 79515 bytes is `77.6kb`, not `77.7kb`.

    Measured: Elasticsearch cuts the second decimal rather than rounding it,
    and writes no decimal at all when it would be a zero.
    """
    cut = int(size * 10) / 10
    return f"{cut:.1f}".removesuffix(".0")


def _cat_response(
    rows: list[dict], format: str, *, headers: bool, columns: str,  # noqa: A002
    order: str = "", byte_unit: str = "",
) -> Response:
    """A `_cat` answer, as json or as the text table that is its default.

    Every `_cat` endpoint answers a *table* unless the caller asks for json,
    and mockdr answered json regardless — so a script reading columns got a
    document. The columns are padded to their widest value, `v` adds the
    header row, `h` picks the columns and `s` orders the rows. `h` and `s`
    apply to the json form too, which they did not: a client asking for two
    columns as json was handed all twelve (all measured against 8.15).
    """
    names = [c.strip() for c in columns.split(",") if c.strip()] or (
        list(rows[0]) if rows else []
    )
    if order:
        rows = _cat_sorted(rows, order)
    rows = [
        {
            name: _bytes_as(value, byte_unit) if name in _BYTE_COLUMNS else value
            for name, value in row.items()
        }
        for row in rows
    ]
    if format.lower() == "json":
        return JSONResponse(content=[
            {name: row.get(name, "") for name in names if name in row} for row in rows
        ] if columns else rows)
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


@router.get(
    "/_security/_authenticate",
    dependencies=[es_refuses_unknown(source=False)],
)
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


@router.get(
    "/_search",
    operation_id="es_search_all_get",
    dependencies=[es_refuses_unknown(*_SEARCH_PARAMS)],
)
@router.post(
    "/_search",
    operation_id="es_search_all_post",
    dependencies=[es_refuses_unknown(*_SEARCH_POST_PARAMS)],
)
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


#: A time value is a number and one of seven units — `w` and `y` are *not*
#: among them here, though other parts of the stack take them.  A negative
#: one is fine.  Anything else is `unit is missing or unrecognized`, measured
#: on 8.15 unit by unit.
_TIME_VALUE = re.compile(r"-?\d+(?:\.\d+)?(?:nanos|micros|ms|s|m|h|d)")

def _with_uri_params(body: dict, query: Mapping[str, str]) -> dict:
    """Fold the URI-search parameters into the body they stand for."""
    # Before the early return below: a time value is judged whether or not
    # anything else in the query reaches the body.
    for name in ("timeout", "scroll"):
        value = query.get(name)
        if value is not None and not _TIME_VALUE.fullmatch(value):
            raise ESQueryError(
                f"failed to parse setting [{name}] with value [{value}] "
                f"as a time value: unit is missing or unrecognized",
                es_type="illegal_argument_exception",
            )
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
                # `illegal_argument_exception`, not the `parsing_exception`
                # the body's own failures carry: the uri parameters are read
                # before the body is parsed at all.  Measured on 8.15.
                raise ESQueryError(
                    f"Failed to parse int parameter [{name}] with value "
                    f"[{given[name]}]",
                    es_type="illegal_argument_exception",
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


#: The only member `_count` takes in its body. Everything else is refused by
#: name — including `size` and `aggs`, which the neighbouring `_search`
#: takes, so a client reusing a search body here is told so rather than
#: quietly counted with the parameter dropped.
_COUNT_BODY_KEYS = frozenset({"query"})


def _checked_count_body(body: dict) -> dict:
    """Refuse a `_count` body member Elasticsearch does not support."""
    for key in body:
        if key not in _COUNT_BODY_KEYS:
            raise HTTPException(status_code=400, detail=build_es_error_response(
                400, "parsing_exception", f"request does not support [{key}]",
                {"line": 1, "col": 2},
            ))
    return body


@router.get(
    "/_count",
    operation_id="es_count_all_get",
    dependencies=[es_refuses_unknown(*_COUNT_PARAMS)],
)
@router.post(
    "/_count",
    operation_id="es_count_all_post",
    dependencies=[es_refuses_unknown(*_COUNT_POST_PARAMS)],
)
def es_count_all(
    request: Request,
    body: dict = Body(default={}),
    ignore_unavailable: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Count across every index; the route was missing, like ``/_search`` was."""
    return search_queries.es_count(
        "_all", _with_uri_params(_checked_count_body(body), request.query_params),
        ignore_unavailable=ignore_unavailable,
    )


async def _mget_body(request: Request) -> dict:
    """The documents an mget asks for, refusing the two ways it can be empty.

    8.15 tells them apart: no body at all is a `parse_exception` saying a
    body or a `source` parameter is required, and a body naming no documents
    is an `action_request_validation_exception`. The per-index route made
    neither distinction — it answered `{"docs": []}`, an empty result
    reported as a successful lookup of nothing.
    """
    raw = await request.body()
    if not raw.strip() and not request.query_params.get("source"):
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "parse_exception", "request body or source parameter is required",
        ))
    try:
        body = json.loads(raw or request.query_params.get("source") or "{}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "parse_exception", "request body is required",
        )) from exc
    if not isinstance(body, dict) or (not body.get("docs") and not body.get("ids")):
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception",
            "Validation Failed: 1: no documents to get;",
        ))
    return body


@router.get("/_mget", operation_id="es_mget_all_get")
@router.post("/_mget", operation_id="es_mget_all_post")
async def es_mget_all(
    request: Request,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Fetch documents by ``docs`` entries that each name their own index."""
    return search_queries.es_mget("_all", await _mget_body(request))


@router.post("/_bulk", operation_id="es_bulk")
@router.put("/_bulk", operation_id="es_bulk_put")
async def es_bulk(
    request: Request,
    refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Index documents from NDJSON action/source pairs.

    Both refusals measured on 8.15: an empty body is parse_exception
    "request body is required"; a body that is not JSON is
    x_content_parse_exception with Jackson's diagnostic.

    Each action does what it says. It used to do only one thing: every line,
    whatever verb it named, was indexed. So a `create` overwrote the document
    it was meant to refuse to touch, a `delete` wrote instead of deleting, an
    `update` of something absent created it — and `errors` was reported as
    `false` throughout, which is the one field a client checks. Bulk is how
    everything is written at scale, and none of it was.
    """
    raw = (await request.body()).decode("utf-8", errors="replace")
    lines = [line for line in raw.split("\n") if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "parse_exception", "request body is required",
        ))
    items: list[dict] = []
    # `_bulk` obeys the same near-real-time rule as a single write: nothing
    # it indexes is searchable until a refresh, and nothing it deletes stops
    # being searchable until one.  Measured on 8.15.
    forced = _makes_visible(refresh)
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
        items.append({verb: _bulk_action(verb, index, doc_id, doc,
                                         refresh=forced)})
        i += 1
    errors = any(
        int(next(iter(item.values())).get("status", 200)) >= 400 for item in items
    )
    return {"errors": errors, "took": 1, "items": items}


def _bulk_item_error(index: str, doc_id: str, status: int,
                     kind: str, reason: str) -> dict:
    """One failed bulk item, which carries an error instead of a result."""
    return {
        "_index": index, "_id": doc_id, "status": status,
        "error": {
            "type": kind, "reason": reason,
            "index_uuid": search_queries.es_index_uuid(index),
            "shard": "0", "index": index,
        },
    }


def _bulk_action(verb: str, index: str, doc_id: str, doc: dict, *,
                 refresh: bool = False) -> dict:
    """Carry out one bulk action, in the shape its own verb answers with."""
    if verb == "delete":
        result = search_queries.es_delete_doc(index, doc_id, refresh=refresh)
        if result is not None:
            return {**result, "status": 200}
        # A delete that found nothing still moves the shard's sequence, and
        # answers the document envelope with `not_found` — not an error item.
        return {
            "_index": index, "_id": doc_id, "_version": 1, "result": "not_found",
            "_shards": {"total": 2, "successful": 1, "failed": 0},
            "_seq_no": search_queries.next_seq_no(index), "_primary_term": 1,
            "status": 404,
        }

    if verb == "create" and search_queries.document_exists(index, doc_id):
        version = search_queries.document_version(index, doc_id)
        return _bulk_item_error(
            index, doc_id, 409, "version_conflict_engine_exception",
            f"[{doc_id}]: version conflict, document already exists "
            f"(current version [{version}])",
        )

    if verb == "update":
        try:
            result = search_queries.es_update_doc(index, doc_id, doc)
        except search_queries.DocumentMissingError:
            return _bulk_item_error(
                index, doc_id, 404, "document_missing_exception",
                f"[{doc_id}]: document missing",
            )
        return {**result, "status": 200}

    result = search_queries.es_index_doc(index, doc_id, doc, refresh=refresh)
    return {**result, "status": 201 if result.get("result") == "created" else 200}


_BULK_VERBS = frozenset({"create", "delete", "index", "update"})
_JSON_TOKEN_OF = {list: "START_ARRAY", str: "VALUE_STRING", int: "VALUE_NUMBER",
                  float: "VALUE_NUMBER", type(None): "VALUE_NULL",
                  bool: "VALUE_BOOLEAN"}


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


@router.get(
    "/{index:esindex}/_search",
    operation_id="es_search_get",
    dependencies=[es_refuses_unknown(*_SEARCH_PARAMS)],
)
@router.post(
    "/{index:esindex}/_search",
    operation_id="es_search_post",
    dependencies=[es_refuses_unknown(*_SEARCH_POST_PARAMS)],
)
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


@router.post(
    "/{index:esindex}/_pit",
    operation_id="es_open_pit",
    dependencies=[es_refuses_unknown(*_PIT_PARAMS)],
)
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


@router.post(
    "/_search/scroll",
    operation_id="es_scroll",
    dependencies=[es_refuses_unknown(*_SCROLL_PARAMS)],
)
@router.get(
    "/_search/scroll",
    operation_id="es_scroll_get",
    dependencies=[es_refuses_unknown(
        *_SCROLL_PARAMS,
    )],
)
def scroll_search(
    body: dict = Body(default={}),
    scroll_id_param: str | None = Query(default=None, alias="scroll_id"),
    caller: dict = Depends(require_es_auth),
) -> dict:
    """The next page of a scrolled search.

    The id may come in the query as readily as in the body — the route
    declared `scroll_id` as a query member and then read only the body, so a
    client that scrolled the documented way was told its perfectly good id
    could not be parsed.

    Naming no id at all is a *validation* failure, and validation runs before
    the security layer: `400 Validation Failed: 1: scrollId is missing;`,
    where an id that is present but unparsable is the 403 below.  Measured on
    8.15, with the id absent, in the query, and in the body.
    """
    scroll_id = str(body.get("scroll_id") or scroll_id_param or "")
    if not scroll_id:
        reason = "Validation Failed: 1: scrollId is missing;"
        raise HTTPException(status_code=400, detail={"error": {
            "root_cause": [
                {"type": "action_request_validation_exception", "reason": reason},
            ],
            "type": "action_request_validation_exception",
            "reason": reason,
        }, "status": 400})
    try:
        return search_queries.scroll(scroll_id)
    except search_queries.ScrollIdUnparsableError as exc:
        # A scroll id encodes which indices the scroll reads, so one the
        # cluster cannot parse cannot be authorised either — 8.15 refuses it
        # in the security layer, before the search context is looked for,
        # and names the parse failure as the cause. Measured.
        user = str(caller.get("user") or "elastic")
        denied = (
            f"action [indices:data/read/scroll] is unauthorized for user [{user}] "
            f"with effective roles [{caller.get('role', 'superuser')}], this action "
            f"is granted by the index privileges [read,all]"
        )
        raise HTTPException(status_code=403, detail={"error": {
            "root_cause": [{"type": "security_exception", "reason": denied}],
            "type": "security_exception",
            "reason": denied,
            "caused_by": {
                "type": "illegal_argument_exception",
                "reason": "Cannot parse scroll id",
                "caused_by": {"type": "e_o_f_exception", "reason": None},
            },
        }, "status": 403}) from exc
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


@router.delete(
    "/_search/scroll",
    operation_id="es_clear_scroll",
    dependencies=[es_refuses_unknown(*_SCROLL_DELETE_PARAMS)],
)
def clear_scroll(body: dict = Body(default={}), _: dict = Depends(require_es_auth)) -> dict:
    """Free a scroll the client is done with."""
    return search_queries.close_context(str(body.get("scroll_id", "")))


@router.get(
    "/{index:esindex}/_count",
    operation_id="es_count_get",
    dependencies=[es_refuses_unknown(*_COUNT_PARAMS)],
)
@router.post(
    "/{index:esindex}/_count",
    operation_id="es_count_post",
    dependencies=[es_refuses_unknown(*_COUNT_POST_PARAMS)],
)
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
            index, _with_uri_params(_checked_count_body(body), request.query_params),
            ignore_unavailable=ignore_unavailable,
        )
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get("/{index:esindex}/_mget", operation_id="es_mget_get")
@router.post("/{index:esindex}/_mget", operation_id="es_mget_post")
async def es_mget(
    index: str,
    request: Request,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Fetch several documents by id in one request."""
    return search_queries.es_mget(index, await _mget_body(request))



# ── Mapping / Stats ──────────────────────────────────────────────────────────


@router.get(
    "/{index:esindex}/_mapping",
    dependencies=[es_refuses_unknown(*_MAPPING_PARAMS, source=False)],
)
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


@router.get(
    "/{index:esindex}/_mapping/field/{field}",
    dependencies=[es_refuses_unknown(*_FIELD_MAPPING_PARAMS, source=False)],
)
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


# A mapping update is accepted on both verbs, and the two do the same
# thing: `acknowledged` either way, and both fields land.  Measured on
# 8.15 by putting one field and posting another to the same index.
@router.post("/{index:esindex}/_mapping", operation_id="es_post_mapping")
@router.put("/{index:esindex}/_mapping", operation_id="es_put_mapping")
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


@router.get(
    "/{index:esindex}/_field_caps",
    operation_id="es_field_caps_get",
    dependencies=[es_refuses_unknown(*_FIELD_CAPS_PARAMS)],
)
@router.post(
    "/{index:esindex}/_field_caps",
    operation_id="es_field_caps_post",
    dependencies=[es_refuses_unknown(*_FIELD_CAPS_POST_PARAMS)],
)
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


@router.post(
    "/{index:esindex}/_update/{doc_id}",
    operation_id="es_update_doc",
    dependencies=[es_refuses_unknown(*_UPDATE_PARAMS, source=False)],
)
def update_doc(
    index: str,
    doc_id: str,
    if_seq_no: int | None = Query(default=None),
    if_primary_term: int | None = Query(default=None),
    body: dict = Body(...),
    refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> JSONResponse:
    """Apply a partial document or a script to one document."""
    forced = _forced_refresh(refresh)
    search_queries.check_precondition(index, doc_id, if_seq_no, if_primary_term)
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


@router.post(
    "/{index:esindex}/_update_by_query",
    operation_id="es_update_by_query",
    dependencies=[es_refuses_unknown(*_UPDATE_BY_QUERY_PARAMS)],
)
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


@router.post(
    "/{index:esindex}/_delete_by_query",
    operation_id="es_delete_by_query",
    dependencies=[es_refuses_unknown(*_DELETE_BY_QUERY_PARAMS)],
)
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


@router.get(
    "/{index:esindex}/_source/{doc_id}",
    operation_id="es_get_source",
    dependencies=[es_refuses_unknown(*_DOC_SOURCE_PARAMS, source=False)],
)
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


# `_refresh` and `_flush` answer a GET exactly as they answer a POST — the
# same body, byte for byte — while `_forcemerge` and `_cache/clear` below
# refuse it with a 405.  Measured on 8.15; no rule accounts for the split.
@router.get(
    "/{index:esindex}/_refresh",
    operation_id="es_refresh_get",
    dependencies=[es_refuses_unknown(*_REFRESH_PARAMS, source=False)],
)
@router.get(
    "/{index:esindex}/_flush",
    operation_id="es_flush_get",
    dependencies=[es_refuses_unknown(*_FLUSH_PARAMS, source=False)],
)
@router.post(
    "/{index:esindex}/_refresh",
    operation_id="es_refresh",
    dependencies=[es_refuses_unknown(*_REFRESH_PARAMS, source=False)],
)
@router.post(
    "/{index:esindex}/_flush",
    operation_id="es_flush",
    dependencies=[es_refuses_unknown(*_FLUSH_PARAMS, source=False)],
)
@router.post(
    "/{index:esindex}/_forcemerge",
    operation_id="es_forcemerge",
    dependencies=[es_refuses_unknown(*_FORCEMERGE_PARAMS, source=False)],
)
@router.post(
    "/{index:esindex}/_cache/clear",
    operation_id="es_cache_clear",
    dependencies=[es_refuses_unknown(*_CACHE_CLEAR_PARAMS, source=False)],
)
def refresh_index(request: Request, index: str,
                  _: dict = Depends(require_es_auth)) -> dict:
    """Answer the maintenance calls that follow a write.

    `_refresh` is the one that does something: it makes pending writes
    searchable and drops what was deleted.  The others are acknowledged and
    change nothing, which is what a mock holding its documents in memory has
    to do with a flush or a force-merge.
    """
    try:
        search_queries.es_get_stats(index)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    if request.url.path.endswith("/_refresh"):
        search_queries.refresh_index(index)
    return dict(_SHARD_ACK)


# Every search-shaped endpoint takes the body on a GET as readily as on a
# POST, which is how a client that puts its query in the body and reads it
# with a GET reaches them.  Measured identical on 8.15.
@router.get("/_msearch", operation_id="es_msearch_all_get")
@router.get("/{index:esindex}/_msearch", operation_id="es_msearch_get")
@router.post("/_msearch", operation_id="es_msearch_all")
@router.post("/{index:esindex}/_msearch", operation_id="es_msearch")
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


@router.get(
    "/{index:esindex}/_settings",
    operation_id="es_get_settings",
    dependencies=[es_refuses_unknown(*_SETTINGS_PARAMS, source=False)],
)
def get_settings(index: str, _: dict = Depends(require_es_auth)) -> dict:
    """An index's settings, which is the half of it a client tunes."""
    try:
        return search_queries.index_settings(index)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.put("/{index:esindex}/_settings", operation_id="es_put_settings")
def put_settings(
    index: str, body: dict = Body(...), _: dict = Depends(require_es_write),
) -> dict:
    """Change an index's settings."""
    try:
        return search_queries.put_settings(index, body)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.put(
    "/{index:esindex}/_alias/{alias}",
    operation_id="es_put_alias",
    dependencies=[es_refuses_unknown(*_ALIAS_WRITE_PARAMS, source=False)],
)
def put_alias(index: str, alias: str, _: dict = Depends(require_es_write)) -> dict:
    """Point an alias at an index."""
    try:
        return search_queries.put_alias(index, alias)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.delete(
    "/{index:esindex}/_alias/{alias}",
    operation_id="es_delete_alias",
    dependencies=[es_refuses_unknown(*_ALIAS_WRITE_PARAMS, source=False)],
)
def delete_alias(index: str, alias: str, _: dict = Depends(require_es_write)) -> dict:
    """Take an alias off an index."""
    try:
        return search_queries.delete_alias(index, alias)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get(
    "/{index:esindex}/_alias",
    operation_id="es_get_index_alias",
    dependencies=[es_refuses_unknown(*_ALIAS_PARAMS, source=False)],
)
def get_index_alias(index: str, _: dict = Depends(require_es_auth)) -> dict:
    """Which aliases an index carries."""
    if not search_queries.index_exists(index):
        raise _missing_index(IndexNotFoundError(index))
    return search_queries.alias_map(index)


@router.get(
    "/{index:esindex}/_alias/{alias}",
    operation_id="es_get_index_alias_by_name",
    dependencies=[es_refuses_unknown(*_ALIAS_PARAMS, source=False)],
)
def get_index_alias_by_name(
    index: str, alias: str, _: dict = Depends(require_es_auth),
) -> dict:
    """One alias on one index, which nothing here served at all.

    A client asking whether an index carries a particular alias — with `GET`
    or, more often, with the `HEAD` that means exactly that question — got
    405 from a mount that has the route under two other spellings. An alias
    the index does not carry is 404 `alias [x] missing`, with the bare
    `{error, status}` envelope the cluster uses for it rather than the nested
    one (measured on 8.15).
    """
    if not search_queries.index_exists(index):
        raise _missing_index(IndexNotFoundError(index))
    carried = search_queries.alias_map(index).get(index, {}).get("aliases", {})
    if alias not in carried:
        raise HTTPException(status_code=404, detail={
            "error": f"alias [{alias}] missing", "status": 404,
        })
    return {index: {"aliases": {alias: carried[alias]}}}


@router.post("/_aliases", operation_id="es_update_aliases")
def update_aliases(body: dict = Body(...), _: dict = Depends(require_es_write)) -> dict:
    """Add and remove aliases in one request.

    A body with nothing to do is refused rather than answered `acknowledged`:
    a client that built an empty action list — because its own filter matched
    nothing — was told the aliases had been updated.
    """
    for key in body:
        if key != "actions":
            raise HTTPException(status_code=400, detail=build_es_error_response(
                400, "x_content_parse_exception",
                f"[1:2] [aliases] unknown field [{key}]",
            ))
    actions = body.get("actions")
    if not isinstance(actions, list) and actions is not None:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "x_content_parse_exception",
            "[1:12] [aliases] actions doesn't support values of type: VALUE_STRING",
        ))
    if not actions:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "illegal_argument_exception", "No action specified",
        ))
    try:
        return search_queries.update_aliases(actions)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get(
    "/_alias",
    operation_id="es_get_all_aliases",
    dependencies=[es_refuses_unknown(*_ALIAS_PARAMS, source=False)],
)
def get_all_aliases(_: dict = Depends(require_es_auth)) -> dict:
    """Every index and the aliases it carries.

    The cluster serves this; mockdr read `_alias` as an index name and
    answered `invalid_index_name_exception`.  Found by asking what a trailing
    slash does — `/_alias/` strips to `/_alias`, which turned out to be a
    route nobody had.
    """
    return search_queries.alias_map()


@router.get(
    "/_alias/{alias}",
    operation_id="es_get_alias",
    dependencies=[es_refuses_unknown(*_ALIAS_PARAMS, source=False)],
)
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


@router.get(
    "/_resolve/index/{expression}",
    operation_id="es_resolve_index",
    dependencies=[es_refuses_unknown(*_RESOLVE_PARAMS, source=False)],
)
def resolve_index(expression: str, _: dict = Depends(require_es_auth)) -> dict:
    """What a name stands for: indices, aliases and data streams."""
    return search_queries.resolve_index(expression)


@router.get("/{index:esindex}/_analyze", operation_id="es_analyze_get")
@router.post("/{index:esindex}/_analyze", operation_id="es_analyze")
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


@router.get(
    "/{index:esindex}/_validate/query",
    operation_id="es_validate_query_get",
    dependencies=[es_refuses_unknown(*_VALIDATE_QUERY_PARAMS)],
)
@router.post(
    "/{index:esindex}/_validate/query",
    operation_id="es_validate_query",
    dependencies=[es_refuses_unknown(*_VALIDATE_QUERY_PARAMS)],
)
async def validate_query(
    index: str,
    request: Request,
    explain: bool = Query(default=False),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Whether a query would run, without running it.

    A body it cannot even parse is what this route is *for*: 8.15 answers
    `{"valid": false}` and 200, where every other route answers a parse
    error. mockdr let FastAPI refuse the body first, so a client asking
    whether its query was valid was told its request was malformed instead
    — which is the same news in a shape the client does not read.
    """
    raw = await request.body()
    # `None` for nothing sent, which is nothing to find fault with and so
    # valid; an unreadable body is the route's own answer rather than a
    # refusal.
    body: dict | None = None
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"valid": False}
        if not isinstance(parsed, dict):
            return {"valid": False}
        body = parsed
    try:
        return search_queries.validate_query(index, body, explain=explain)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception", str(exc),
        )) from exc


@router.get("/{index:esindex}/_terms_enum", operation_id="es_terms_enum_get")
@router.post("/{index:esindex}/_terms_enum", operation_id="es_terms_enum")
def terms_enum(
    index: str, body: dict = Body(default={}), _: dict = Depends(require_es_auth),
) -> dict:
    """The values of a field, which is what an autocomplete asks for."""
    try:
        return search_queries.terms_enum(index, body)
    except IndexNotFoundError as exc:
        raise _missing_index(exc) from exc


@router.get(
    "/{index:esindex}/_stats",
    dependencies=[es_refuses_unknown(*_STATS_PARAMS, source=False)],
)
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


@router.get(
    "/{index:esindex}/_doc/{doc_id}",
    dependencies=[es_refuses_unknown(*_DOC_PARAMS, source=False)],
)
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


@router.post("/{index:esindex}/_doc/{doc_id}", operation_id="es_index_doc_post")
@router.put("/{index:esindex}/_doc/{doc_id}", operation_id="es_index_doc_put")
def index_doc(
    index: str,
    doc_id: str,
    if_seq_no: int | None = Query(default=None),
    if_primary_term: int | None = Query(default=None),
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
    search_queries.check_precondition(index, doc_id, if_seq_no, if_primary_term)
    result = search_queries.es_index_doc(
        index, doc_id, body, refresh=_makes_visible(refresh))
    if forced:
        result["forced_refresh"] = True
    # 201 the first time, 200 for a replacement — which is how a client tells
    # a create from an update without reading the body.
    created = result.get("result") == "created"
    return JSONResponse(status_code=201 if created else 200, content=result)


def _makes_visible(refresh: str | None) -> bool:
    """Whether the write is searchable at once, refusing a value ES refuses."""
    _forced_refresh(refresh)          # the same values, refused the same way
    return search_queries.refresh_makes_visible(refresh)


def _forced_refresh(refresh: str | None) -> bool:
    """Read the ``refresh`` parameter, refusing a value Elasticsearch refuses."""
    try:
        return search_queries.refresh_forced(refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "illegal_argument_exception", str(exc),
        )) from exc


@router.put(
    "/{index:esindex}",
    operation_id="es_create_index",
    dependencies=[es_refuses_unknown(*_PUT_INDEX_PARAMS, source=False)],
)
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


@router.get(
    "/{index:esindex}",
    operation_id="es_get_index",
    dependencies=[es_refuses_unknown(*_INDEX_PARAMS, source=False)],
)
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


@router.delete("/", operation_id="es_delete_index_unnamed")
@router.delete(
    "/{index:esindex}",
    operation_id="es_delete_index",
    dependencies=[es_refuses_unknown(*_DELETE_INDEX_PARAMS, source=False)],
)
def delete_index(index: str = "", _: dict = Depends(require_es_write)) -> dict:
    """Delete an index and everything written to it.

    `DELETE /` reaches the same endpoint with nothing named, and the cluster
    says so rather than refusing the verb: a client that built its URL from
    an empty variable gets told which argument is missing.  Measured on 8.15.
    """
    if not index:
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception",
            "Validation Failed: 1: index / indices is missing;",
        ))
    if index.startswith("_"):
        raise HTTPException(status_code=400, detail=build_es_invalid_index_name(index))
    result = search_queries.delete_index(index)
    if result is None:
        raise HTTPException(
            status_code=404, detail=build_es_index_not_found(index),
        )
    return result


@router.delete(
    "/{index:esindex}/_doc/{doc_id}",
    dependencies=[es_refuses_unknown(*_DOC_DELETE_PARAMS, source=False)],
)
def delete_doc(
    index: str,
    doc_id: str,
    if_seq_no: int | None = Query(default=None),
    if_primary_term: int | None = Query(default=None),
    refresh: str | None = Query(default=None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete a document written through the index API."""
    forced = _forced_refresh(refresh)
    search_queries.check_precondition(index, doc_id, if_seq_no, if_primary_term)
    result = search_queries.es_delete_doc(
        index, doc_id, refresh=_makes_visible(refresh))
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
