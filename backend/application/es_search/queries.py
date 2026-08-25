"""Elasticsearch REST API query handlers for the mock server.

Routes search requests to the appropriate in-memory collection based on the
index pattern, applies Elasticsearch query DSL, and returns standard ES
response envelopes.
"""
from __future__ import annotations

import hashlib
import time
from fnmatch import fnmatch

from application.es_alerts.commands import update_alert_status
from repository.es_alert_repo import es_alert_repo
from repository.es_endpoint_repo import es_endpoint_repo
from repository.store import store
from utils.es_aggs import apply_aggregations
from utils.es_ecs import to_ecs_document
from utils.es_mapping import (
    FIELDDATA_DISABLED,
    field_capabilities,
    flatten_properties,
    infer_properties,
    merge_properties,
)
from utils.es_painless import PainlessError, run_script
from utils.es_query import (
    ESQueryError,
    apply_es_query,
    apply_source_filter,
    build_predicate,
    doc_positions,
    emits_sort_values,
    hit_id,
    parse_sort_keys,
    sort_field_kinds,
    validate_search_body,
    wrap_as_hits,
)
from utils.es_response import build_es_index_not_found, build_es_search_response
from utils.nested import get_nested
from utils.serde import record_dict

#: How far Elasticsearch counts before it reports ``relation: "gte"`` instead
#: of an exact total (``index.max_result_window``'s sibling default).
DEFAULT_TRACK_TOTAL_HITS = 10_000

# ── Index pattern routing ────────────────────────────────────────────────────

class IndexNotFoundError(LookupError):
    """Raised when a concrete index does not exist.

    Elasticsearch answers a missing *concrete* index with ``404
    index_not_found_exception``; returning an empty result set instead would
    tell a caller the index exists and holds nothing, which is a different
    fact and one they cannot act on.
    """

    def __init__(self, index: str) -> None:
        """Record the index name so the 404 body can name it."""
        self.index = index
        super().__init__(f"no such index [{index}]")


class IndexExistsError(ValueError):
    """Raised when a client creates an index that is already there.

    Elasticsearch answers ``resource_already_exists_exception``; silently
    acknowledging the second create would let a client believe it had a fresh
    index and then find another run's documents in it.
    """

    def __init__(self, index: str, uuid: str) -> None:
        """Record the index and the uuid the message quotes."""
        self.index = index
        self.uuid = uuid
        super().__init__(f"index [{index}/{uuid}] already exists")


def create_index(
    index: str, settings: dict | None = None, mappings: dict | None = None,
) -> dict:
    """Create an index, and report it the way Elasticsearch does.

    The mappings a client sends are kept: a cluster echoes them back from
    ``GET /{index}`` and answers ``_field_caps`` from them, and mockdr threw
    them away — so a data view built against the mock saw an index with no
    fields at all.

    Raises:
        IndexExistsError: If the index is already there.
    """
    existing = store.get("es_indices", index)
    if existing:
        raise IndexExistsError(index, str(existing.get("uuid", "")))
    store.save("es_indices", index, {
        "uuid": _index_uuid(index), "settings": dict(settings or {}), "docs": 0,
        "created": int(time.time() * 1000),
        "properties": dict((mappings or {}).get("properties") or {}),
    })
    return {"acknowledged": True, "shards_acknowledged": True, "index": index}


def delete_index(index: str) -> dict | None:
    """Delete an index and the documents written to it, or ``None`` if absent."""
    if not store.get("es_indices", index):
        return None
    for key in list(store.get_all_with_keys("es_documents")):
        if key.startswith(f"{index}:"):
            store.delete("es_documents", key)
    store.delete("es_indices", index)
    return {"acknowledged": True}


def index_properties(index: str) -> dict:
    """Everything the index maps: what was declared, plus what was written.

    A cluster adds a field to the mapping the first time a document carries
    it, and never changes one already there.
    """
    entry = store.get("es_indices", index) or {}
    properties: dict = dict(entry.get("properties") or {})
    for _doc_id, source in _written_documents(index):
        properties = merge_properties(properties, infer_properties(source))
    return properties


def put_mapping(index: str, body: dict) -> dict:
    """Add fields to an index's mapping, refusing a type change.

    Raises:
        IndexNotFoundError:   If the index is not there.
        MappingConflictError: If a field's type would change.
    """
    entry = store.get("es_indices", index)
    if entry is None:
        raise IndexNotFoundError(index)
    # Checked against what the index *maps*, not only what was declared: a
    # field a document introduced is mapped too, and a cluster refuses to
    # change its type just the same.
    merged = merge_properties(
        index_properties(index), dict(body.get("properties") or {}), strict=True,
    )
    store.save("es_indices", index, {**entry, "properties": merged})
    return {"acknowledged": True}


def es_field_caps(index: str, fields: list[str]) -> dict:
    """The ``_field_caps`` body, which every Kibana data view asks for.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown.
    """
    missing = _missing_target(index)
    if missing is not None:
        raise IndexNotFoundError(missing)
    names = [t.strip() for t in index.lower().split(",") if t.strip()]
    properties: dict = {}
    for name in names:
        properties = merge_properties(properties, _mapped_properties(name))
    return {
        "indices": names,
        "fields": field_capabilities(properties, fields),
    }


def _mapped_properties(index: str) -> dict:
    """The properties for one index, canned patterns included."""
    canned = _canned_properties(index)
    return merge_properties(canned, index_properties(index)) if canned else (
        index_properties(index)
    )


def describe_index(index: str) -> dict | None:
    """The index metadata ``GET /{index}`` answers with, or ``None`` if absent.

    Elasticsearch keys the document by the index name and reports every
    setting as a *string*, which is what a client parsing `number_of_shards`
    has to cope with.
    """
    entry = store.get("es_indices", index)
    if entry is None and index.startswith(_KNOWN_PREFIXES):
        entry = {"uuid": _index_uuid(index), "settings": {}}
    if entry is None:
        return None
    settings = {str(k): str(v) for k, v in (entry.get("settings") or {}).items()}
    return {
        index: {
            "aliases": {},
            "mappings": (
                {"properties": index_properties(index)}
                if index_properties(index) else {}
            ),
            "settings": {"index": {
                "number_of_shards": settings.get("number_of_shards", "1"),
                "number_of_replicas": settings.get("number_of_replicas", "0"),
                "provided_name": index,
                "creation_date": str(entry.get("created", 0)),
                "uuid": str(entry.get("uuid", "")),
                "version": {"created": "8512000"},
            }},
        },
    }


def index_exists(index: str) -> bool:
    """Whether a client can search this index — created here or seeded."""
    return bool(store.get("es_indices", index)) or index.startswith(_KNOWN_PREFIXES)


def created_indices() -> list[str]:
    """Every index a client created, for ``_cat/indices``."""
    return sorted(store.get_all_with_keys("es_indices"))


def _written_documents(index: str) -> list[tuple[str, dict]]:
    """The documents a client wrote to this index, with the ids it gave them.

    The count on the registry entry keeps this off the hot path: an index
    nobody has written to costs one dict lookup rather than a scan of every
    document in the store.
    """
    entry = store.get("es_indices", index) or {}
    if not entry.get("docs"):
        return []
    prefix = f"{index}:"
    return [
        (key[len(prefix):], dict(record.get("_source") or {}))
        for key, record in store.get_all_with_keys("es_documents").items()
        if key.startswith(prefix)
    ]


#: Index-name prefixes this mock actually backs, grouped by their source.
_ALERT_PREFIXES: tuple[str, ...] = (".siem-signals", ".alerts-security")
_ENDPOINT_PREFIXES: tuple[str, ...] = ("metrics-endpoint", "logs-endpoint")
_KNOWN_PREFIXES: tuple[str, ...] = _ALERT_PREFIXES + _ENDPOINT_PREFIXES


def _pattern_hits(name: str, prefixes: tuple[str, ...]) -> bool:
    """Return whether an index expression selects any of *prefixes*.

    The mock stores prefixes where a real cluster holds dated concrete names,
    so a pattern matches if it selects the prefix itself *or* any name beneath
    it — ``logs-*`` and ``.siem-signals-*`` both hit. Matching is delegated to
    :mod:`fnmatch` rather than a literal-prefix comparison, which treated every
    leading-wildcard pattern as matching everything: ``*zzz`` selected the
    whole cluster instead of nothing.
    """
    if name in ("_all", "*"):
        return True
    if "*" in name:
        return any(
            fnmatch(prefix, name) or fnmatch(f"{prefix}-suffix", name)
            for prefix in prefixes
        )
    return name.startswith(prefixes)


def _missing_target(index: str) -> str | None:
    """Return the first target in *index* that cannot be resolved.

    Elasticsearch accepts a comma-separated list of targets and only refuses
    the ones it must: a *concrete* name that does not exist. A wildcard, or the
    ``_all`` alias, resolving to nothing is governed by ``allow_no_indices``,
    which defaults to true — so those stay a 200 with no hits rather than a
    404. Conflating the two would make a legitimate empty search look broken.

    Args:
        index: Raw index expression from the request path.

    Returns:
        The offending target name, or ``None`` when every target is resolvable.
    """
    for target in index.split(","):
        raw = target.strip()
        name = raw.lower()
        if not name or name == "_all" or "*" in name:
            continue
        # Elasticsearch rejects uppercase index names outright, so a target
        # that only matches when folded cannot name a real index.
        if raw != name or not index_exists(name):
            return raw
    return None


def known_index_prefixes() -> tuple[str, ...]:
    """Return the index prefixes this mock serves, for docs and diagnostics."""
    return _KNOWN_PREFIXES


#: Sort keys that name a document's position or score rather than a field.
_SORT_METADATA = frozenset({"_doc", "_score", "_id", "_index"})


def _refuse_unsortable(index: str, sort_spec: list) -> None:
    """Refuse a sort a real cluster cannot run.

    A cluster sorts on doc values, so a `text` field is refused for the same
    reason it cannot be aggregated, and a field the mapping does not have at
    all is refused as well — unless the client says what type to assume.
    Only an index mockdr holds a full mapping for is judged: for its own
    collections the mapping is a summary, and refusing a sort on a field it
    does not happen to list would be inventing a failure.

    Raises:
        ESQueryError: If a sort key cannot be run.
    """
    entry = store.get("es_indices", index)
    if not entry or not sort_spec:
        return
    properties = flatten_properties(_mapped_properties(index))
    for key in sort_spec:
        name, spec = _sort_key_name(key)
        if not name or name in _SORT_METADATA or spec.get("unmapped_type"):
            continue
        mapped = properties.get(name)
        if mapped is None or mapped.get("type") == "object":
            raise ESQueryError(
                f"No mapping found for [{name}] in order to sort on",
                es_type="query_shard_exception", shard_failure=True,
            )
        if mapped.get("type") == "text":
            raise ESQueryError(
                FIELDDATA_DISABLED.format(field=name, index=index),
                es_type="illegal_argument_exception", shard_failure=True,
            )


def _sort_key_name(key: object) -> tuple[str, dict]:
    """The field one sort key names, and whatever it says about it."""
    if isinstance(key, str):
        return key, {}
    if isinstance(key, dict) and key:
        name, spec = next(iter(key.items()))
        return str(name), spec if isinstance(spec, dict) else {}
    return "", {}


def _terms_lookup(index: str, doc_id: str, path: str) -> list:
    """The values a ``terms`` lookup points at, read from another document.

    A document that is not there, or a path it does not carry, matches
    nothing; a missing *index* is an error, the way it is on a cluster.
    """
    missing = _missing_target(index)
    if missing is not None:
        raise IndexNotFoundError(missing)
    document = es_get_doc(index, doc_id)
    if not document:
        return []
    value = get_nested(document.get("_source") or {}, path)
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _resolve_collection(
    index: str, *, ignore_unavailable: bool = False,
) -> tuple[list[dict], str, dict[int, str]]:
    """Resolve an index pattern to the backing in-memory collection.

    Args:
        index:              Elasticsearch index name or pattern.
        ignore_unavailable: Skip missing concrete targets instead of failing,
                            mirroring the query parameter of the same name.

    Returns:
        The records, the canonical index name, and the ids of the documents a
        client wrote — keyed by object identity, so a hit can carry the id it
        was given rather than one derived from its contents.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown.
    """
    idx = index.lower()

    if not ignore_unavailable:
        missing = _missing_target(index)
        if missing is not None:
            raise IndexNotFoundError(missing)

    names = [t.strip().lower() for t in idx.split(",") if t.strip()]
    records: list[dict] = []
    if any(_pattern_hits(n, _ALERT_PREFIXES) for n in names):
        # Alerts are rendered as ECS here rather than at the response boundary,
        # so a query written against the real field names (`host.name`,
        # `kibana.alert.severity`) filters and aggregates correctly too.
        records += [to_ecs_document(record_dict(a), idx) for a in es_alert_repo.list_all()]
    if any(_pattern_hits(n, _ENDPOINT_PREFIXES) for n in names):
        records += [record_dict(ep) for ep in es_endpoint_repo.list_all()]
    written: dict[int, str] = {}
    for name in names:
        # A document written through the index API is searchable, as it is on
        # a real cluster; it used to be readable by id and invisible to every
        # search, which is the shape of an ingest that looks like it worked.
        for doc_id, source in _written_documents(name):
            written[id(source)] = doc_id
            records.append(source)
    return records, idx, written


# ── Public query functions ───────────────────────────────────────────────────

def es_search(index: str, body: dict, *, ignore_unavailable: bool = False) -> dict:
    """Execute an Elasticsearch _search against the mock data.

    Args:
        index:              Target index name or pattern.
        body:               Elasticsearch query DSL request body.
        ignore_unavailable: Skip a missing concrete index instead of failing.

    Returns:
        Full Elasticsearch _search response envelope.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown.
    """
    records, canonical_index, written_ids = _resolve_collection(
        index, ignore_unavailable=ignore_unavailable,
    )

    # Capture total before pagination.
    total_before = len(records)

    validate_search_body(body)
    _refuse_unsortable(canonical_index, body.get("sort") or [])
    # Apply query DSL (filter, sort, from/size).
    filtered = apply_es_query(records, body, written_ids, _terms_lookup)

    # If a query clause was provided, the total is the filtered count
    # before from/size pagination; otherwise it's all records.
    query_clause = body.get("query")
    if query_clause:
        # Re-filter without pagination to get the true total.
        predicate = build_predicate(
            query_clause, ids=written_ids, lookup=_terms_lookup,
        )
        total = sum(1 for r in records if predicate(r))
    else:
        total = total_before

    sort_keys = parse_sort_keys(body.get("sort") or [])
    if not emits_sort_values(sort_keys):
        sort_keys = []
    hits = apply_source_filter(
        wrap_as_hits(
            filtered,
            index=canonical_index,
            sort_keys=sort_keys,
            positions=doc_positions(records),
            ids=written_ids,
            kinds=sort_field_kinds(records, sort_keys),
        ),
        body.get("_source"),
    )
    response = build_es_search_response(hits, total, sorted_search=bool(sort_keys))

    # Aggregations run over everything the query matched, not the page.
    aggs = body.get("aggs") or body.get("aggregations")
    if aggs:
        if query_clause:
            # Compiled once, not once per document.
            matches = build_predicate(query_clause)
            matched = [r for r in records if matches(r)]
        else:
            matched = records
        response["aggregations"] = apply_aggregations(
            matched, aggs, index=canonical_index, ids=written_ids,
            properties=lambda: _mapped_properties(canonical_index),
        )

    _apply_total_hits_tracking(
        response, body.get("track_total_hits", DEFAULT_TRACK_TOTAL_HITS), total,
    )

    return response


def _apply_total_hits_tracking(
    response: dict, tracking: bool | int | None, total: int,
) -> None:
    """Report the total the way ``track_total_hits`` asks for.

    Elasticsearch stops counting at 10 000 by default and says so with
    ``relation: "gte"``; a client that trusts an exact count from the mock
    would misread the real cluster's capped one as the whole backlog.
    """
    if tracking is False:
        response["hits"].pop("total", None)
        return
    if tracking is True:
        return
    limit = tracking if isinstance(tracking, int) else DEFAULT_TRACK_TOTAL_HITS
    if total > limit:
        response["hits"]["total"] = {"value": limit, "relation": "gte"}


def es_count(index: str, body: dict, *, ignore_unavailable: bool = False) -> dict:
    """Return a document count, the ``_count`` API's response.

    Args:
        index:              Target index name or pattern.
        body:               Optional body carrying a ``query``.
        ignore_unavailable: Skip a missing concrete index instead of failing.

    Returns:
        ``{"count": N, "_shards": {...}}``.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown.
    """
    records, _, written = _resolve_collection(index, ignore_unavailable=ignore_unavailable)
    query_clause = (body or {}).get("query")
    if query_clause:
        predicate = build_predicate(query_clause, ids=written)
        records = [r for r in records if predicate(r)]
    return {
        "count": len(records),
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    }


def es_cat_indices() -> list[dict]:
    """Return the ``_cat/indices`` rows, in the JSON form ``format=json`` gives."""
    rows = []
    for prefix in _KNOWN_PREFIXES:
        records, _, _written = _resolve_collection(prefix, ignore_unavailable=True)
        rows.append({
            "health": "green",
            "status": "open",
            "index": prefix,
            "uuid": _index_uuid(prefix),
            "pri": "1",
            "rep": "1",
            "docs.count": str(len(records)),
            "docs.deleted": "0",
            "store.size": f"{max(len(records), 1) * 4}kb",
            # Present on 8.15 beside store.size (measured).
            "dataset.size": f"{max(len(records), 1) * 4}kb",
            "pri.store.size": f"{max(len(records), 1) * 4}kb",
        })
    return rows


def es_cluster_health(index: str = "") -> dict:
    """Return the ``_cluster/health`` body."""
    return {
        "cluster_name": "mockdr-elastic",
        "status": "green",
        "timed_out": False,
        "number_of_nodes": 1,
        "number_of_data_nodes": 1,
        "active_primary_shards": len(_KNOWN_PREFIXES),
        "active_shards": len(_KNOWN_PREFIXES),
        "relocating_shards": 0,
        "initializing_shards": 0,
        "unassigned_shards": 0,
        "delayed_unassigned_shards": 0,
        "number_of_pending_tasks": 0,
        "number_of_in_flight_fetch": 0,
        "task_max_waiting_in_queue_millis": 0,
        "active_shards_percent_as_number": 100.0,
        **({"index": index} if index else {}),
    }


def es_mget(index: str, body: dict) -> dict:
    """Return the ``_mget`` response for the requested document ids."""
    docs: list[dict] = []
    for entry in body.get("docs", []) or []:
        target = entry.get("_index") or index
        doc_id = str(entry.get("_id", ""))
        found = None
        try:
            found = es_get_doc(target, doc_id)
        except (IndexNotFoundError, MultipleIndicesError):
            found = None
        docs.append(found or {"_index": target, "_id": doc_id, "found": False})

    for doc_id in body.get("ids", []) or []:
        try:
            found = es_get_doc(index, str(doc_id))
        except (IndexNotFoundError, MultipleIndicesError):
            # A missing index is reported per document, with the request
            # itself still a 200 (measured on 8.15); it used to 500.
            docs.append({
                "_index": index, "_id": str(doc_id),
                "error": build_es_index_not_found(index)["error"],
            })
            continue
        docs.append(found or {"_index": index, "_id": str(doc_id), "found": False})

    return {"docs": docs}


def _document_id(record: dict) -> str:
    """The ``_id`` a record answers to, flat or ECS."""
    return hit_id(record)


def es_index_uuid(index: str) -> str:
    """The uuid an index reports, for a caller outside this module."""
    entry = store.get("es_indices", index) or {}
    return str(entry.get("uuid") or _index_uuid(index))


def _index_uuid(index: str) -> str:
    """A stable pseudo-uuid for an index name."""
    digest = hashlib.sha256(index.encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


class MultipleIndicesError(ValueError):
    """Raised when a single-document route is given more than one target.

    ``_doc`` addresses one document in one index, so Elasticsearch refuses a
    comma list, a wildcard or ``_all`` rather than picking one.
    """


def es_get_doc(index: str, doc_id: str) -> dict | None:
    """Get a single document by ID from the appropriate collection.

    Args:
        index:  Target index name.
        doc_id: Document ID.

    Returns:
        Elasticsearch get response dict, or None if not found.

    Raises:
        MultipleIndicesError: If *index* names more than one target.
        IndexNotFoundError:   If the index is unknown.
    """
    if "," in index or "*" in index or index.lower() == "_all":
        msg = "multiple indices are not allowed for this operation"
        raise MultipleIndicesError(msg)

    written = store.get("es_documents", f"{index}:{doc_id}")
    if written:
        return {
            "_index": index,
            "_id": doc_id,
            "_version": written.get("_version", 1),
            "_seq_no": 0,
            "_primary_term": 1,
            "found": True,
            "_source": written.get("_source", {}),
        }

    records, canonical_index, _written = _resolve_collection(index)

    for rec in records:
        # An ECS document keeps its identity under kibana.alert.uuid or
        # signal.rule.id rather than a top-level `id`.
        if _document_id(rec) == doc_id:
            return {
                "_index": canonical_index,
                "_id": doc_id,
                "_version": 1,
                "_seq_no": 0,
                "_primary_term": 1,
                "found": True,
                "_source": rec,
            }

    return None


#: What ``refresh`` takes, and whether each value forces one. An empty value
#: is the bare `?refresh`, which means true. `wait_for` blocks for the next
#: scheduled refresh rather than forcing one, so it reports nothing.
_REFRESH_VALUES: dict[str, bool] = {
    "": True, "true": True, "false": False, "wait_for": False,
}


def refresh_forced(value: str | None) -> bool:
    """Whether this ``refresh`` value forces one.

    Raises:
        ValueError: For a value Elasticsearch does not take. It refuses the
            write outright rather than guessing at the visibility the client
            asked for.
    """
    if value is None:
        return False
    forced = _REFRESH_VALUES.get(value.lower())
    if forced is None:
        msg = f"Unknown value for refresh: [{value}]."
        raise ValueError(msg)
    return forced


# ---------------------------------------------------------------------------
# Writes: update, update_by_query, delete_by_query
#
# `_update` and the two by-query endpoints were not served at all, so a
# client closing a signal or stamping a field got a 404 from the mock and a
# write from the cluster. All three shapes measured against 8.15, down to
# the `noop` result a change-free update reports and the "[id]: document
# missing" a 404 carries.
# ---------------------------------------------------------------------------

def es_update_doc(index: str, doc_id: str, body: dict) -> dict:
    """Apply a partial document or a script to one document.

    Raises:
        DocumentMissingError: If there is nothing to update and no upsert.
        PainlessError:        If the script is not a form mockdr reads.
    """
    key = f"{index}:{doc_id}"
    existing = store.get("es_documents", key)
    if existing is None:
        upsert = _upsert_source(body)
        if upsert is None:
            raise DocumentMissingError(index, doc_id)
        store.save("es_documents", key, {"_version": 1, "_source": upsert})
        _count_document(index, 1)
        return _write_result(index, doc_id, 1, "created")

    source = dict(existing.get("_source") or {})
    updated = dict(source)
    operation = "index"
    if "script" in body:
        script = body["script"]
        script = {"source": script} if isinstance(script, str) else script
        operation = run_script(
            str(script.get("source", "")), dict(script.get("params") or {}), updated,
        )
    if isinstance(body.get("doc"), dict):
        updated = _deep_merge(updated, body["doc"])

    version = int(existing.get("_version", 1))
    if operation == "delete":
        store.delete("es_documents", key)
        _count_document(index, -1)
        return _write_result(index, doc_id, version + 1, "deleted")
    if operation == "noop" or updated == source:
        # Nothing changed, so nothing was written: no shard did any work.
        return {**_write_result(index, doc_id, version, "noop"),
                "_shards": {"total": 0, "successful": 0, "failed": 0}}
    store.save("es_documents", key, {"_version": version + 1, "_source": updated})
    return _write_result(index, doc_id, version + 1, "updated")


def _upsert_source(body: dict) -> dict | None:
    """The document an update should create, if it asked to create one."""
    if isinstance(body.get("upsert"), dict):
        return dict(body["upsert"])
    if body.get("doc_as_upsert") and isinstance(body.get("doc"), dict):
        return dict(body["doc"])
    if body.get("scripted_upsert"):
        return {}
    return None


def _deep_merge(base: dict, incoming: dict) -> dict:
    """Merge a partial document the way `_update`'s `doc` merges.

    An object is merged field by field rather than replaced: writing
    ``{"nested": {"b": 2}}`` over ``{"nested": {"a": 1}}`` leaves both.
    """
    merged = dict(base)
    for name, value in incoming.items():
        current = merged.get(name)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[name] = _deep_merge(current, value)
        else:
            merged[name] = value
    return merged


def _write_result(index: str, doc_id: str, version: int, result: str) -> dict:
    """The envelope every single-document write answers with."""
    return {
        "_index": index,
        "_id": doc_id,
        "_version": version,
        "result": result,
        "_shards": {"total": 2, "successful": 1, "failed": 0},
        "_seq_no": version - 1,
        "_primary_term": 1,
    }


class DocumentMissingError(LookupError):
    """Raised when an update names a document that is not there."""

    def __init__(self, index: str, doc_id: str) -> None:
        """Record the index and the id, which the 404 names."""
        self.index = index
        self.doc_id = doc_id
        super().__init__(f"[{doc_id}]: document missing")


def es_get_source(index: str, doc_id: str) -> dict | None:
    """A document's ``_source`` alone, or None if it is not there."""
    document = es_get_doc(index, doc_id)
    if not document or not document.get("found", True):
        return None
    source = document.get("_source")
    return dict(source) if isinstance(source, dict) else None


def es_update_by_query(index: str, body: dict) -> dict:
    """Apply a script to every document a query matches."""
    return _by_query(index, body, delete=False)


def es_delete_by_query(index: str, body: dict) -> dict:
    """Delete every document a query matches."""
    return _by_query(index, body, delete=True)


def _by_query(index: str, body: dict, *, delete: bool) -> dict:
    """The shared walk behind ``_update_by_query`` and ``_delete_by_query``.

    mockdr can write the documents a client indexed, and the workflow status
    of its own alerts — the write a SIEM actually makes. Anything else in its
    own collections is a projection of a repository with its own API, and is
    reported as a failure rather than silently counted as written.
    """
    records, canonical, written = _resolve_collection(index)
    clause = body.get("query")
    if clause:
        predicate = build_predicate(clause, ids=written, lookup=_terms_lookup)
        records = [r for r in records if predicate(r)]

    script = body.get("script")
    script = {"source": script} if isinstance(script, str) else (script or {})
    source_text = str(script.get("source", ""))
    params = dict(script.get("params") or {})

    changed = 0
    noops = 0
    failures: list[dict] = []
    for record in records:
        doc_id = written.get(id(record))
        if doc_id is None:
            outcome = _by_query_owned(canonical, record, source_text, params, delete=delete)
            if outcome is None:
                failures.append({
                    "index": canonical,
                    "id": _document_id(record),
                    "cause": {
                        "type": "illegal_argument_exception",
                        "reason": (
                            "mockdr serves this collection from its own API; "
                            "only a workflow status can be written through a query"
                        ),
                    },
                    "status": 400,
                })
                continue
            changed += outcome
            noops += 1 - outcome
            continue
        if delete:
            store.delete("es_documents", f"{canonical}:{doc_id}")
            _count_document(canonical, -1)
            changed += 1
            continue
        result = es_update_doc(canonical, doc_id, {"script": script} if source_text else {})
        changed += result["result"] == "updated"
        noops += result["result"] == "noop"

    return _by_query_response(len(records), changed, noops, failures, delete=delete)


def _by_query_owned(
    index: str, record: dict, source: str, params: dict, *, delete: bool,
) -> int | None:
    """Apply a by-query write to one of mockdr's own records.

    Returns:
        1 if it was written, 0 if the script asked for nothing, or None if
        this is not a write mockdr can make.
    """
    if delete or not source:
        return None
    projected = dict(record)
    try:
        run_script(source, params, projected)
    except PainlessError:
        return None
    status = _written_status(record, projected)
    if status is None:
        return None
    alert_id = _document_id(record)
    return 1 if update_alert_status([alert_id], status)["updated"] else 0


#: Where a signal's workflow status lives, in both spellings a client uses.
_STATUS_PATHS = ("kibana.alert.workflow_status", "signal.status")


def _written_status(before: dict, after: dict) -> str | None:
    """The status a script set, if that is all it set."""
    for path in _STATUS_PATHS:
        old, new = get_nested(before, path), get_nested(after, path)
        if new is not None and new != old:
            return str(new)
    return None


def _by_query_response(
    total: int, changed: int, noops: int, failures: list[dict], *, delete: bool,
) -> dict:
    """The task-shaped body both by-query endpoints answer with."""
    # `_delete_by_query` reports no `updated` member at all;
    # `_update_by_query` reports both, with `deleted` at zero (measured).
    counts = (
        {"deleted": changed} if delete else {"updated": changed, "deleted": 0}
    )
    return {
        "took": 5,
        "timed_out": False,
        "total": total,
        **counts,
        "batches": 1 if total else 0,
        "version_conflicts": 0,
        "noops": noops,
        "retries": {"bulk": 0, "search": 0},
        "throttled_millis": 0,
        "requests_per_second": -1.0,
        "throttled_until_millis": 0,
        "failures": failures,
    }


def es_index_doc(index: str, doc_id: str, body: dict) -> dict:
    """Store a document so a subsequent read finds it.

    The handler previously returned ``result: created`` without writing
    anything, so ``POST _doc`` followed by ``GET _doc`` 404'd — an
    acknowledgement of work never done.

    Args:
        index:  Target index name.
        doc_id: Document id.
        body:   The document.

    Returns:
        The Elasticsearch index-API response.
    """
    key = f"{index}:{doc_id}"
    existing = store.get("es_documents", key)
    version = int(existing.get("_version", 0)) + 1 if existing else 1
    store.save("es_documents", key, {"_version": version, "_source": dict(body)})
    if not existing:
        _count_document(index, 1)
    return {
        "_index": index,
        "_id": doc_id,
        "_version": version,
        "result": "updated" if existing else "created",
        "_shards": {"total": 2, "successful": 1, "failed": 0},
        "_seq_no": version - 1,
        "_primary_term": 1,
    }


def _count_document(index: str, delta: int) -> None:
    """Keep the registry's document count, creating the index if it is new.

    Elasticsearch creates an index on first write, so a client that indexes
    into a name that does not exist yet gets one.
    """
    entry = store.get("es_indices", index) or {
        "uuid": _index_uuid(index), "settings": {}, "docs": 0,
    }
    entry = {**entry, "docs": max(0, int(entry.get("docs", 0)) + delta)}
    store.save("es_indices", index, entry)


def es_delete_doc(index: str, doc_id: str) -> dict | None:
    """Delete a document written through the index API."""
    key = f"{index}:{doc_id}"
    existing = store.get("es_documents", key)
    if not existing:
        return None
    store.delete("es_documents", key)
    _count_document(index, -1)
    return {
        "_index": index,
        "_id": doc_id,
        "_version": int(existing.get("_version", 1)) + 1,
        "result": "deleted",
        "_shards": {"total": 2, "successful": 1, "failed": 0},
        "_seq_no": 0,
        "_primary_term": 1,
    }


def es_get_mapping(index: str, *, ignore_unavailable: bool = False) -> dict:
    """Return a canned index mapping for known index patterns.

    Args:
        index:              Target index name or pattern.
        ignore_unavailable: Skip a missing concrete index instead of failing.

    Returns:
        Elasticsearch mapping response dict.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown, as ``_search``
            and ``_stats`` already do — answering an empty mapping instead said
            the index existed and had no fields.
    """
    if not ignore_unavailable:
        missing = _missing_target(index)
        if missing is not None:
            raise IndexNotFoundError(missing)

    idx = index.lower()
    names = [t.strip() for t in idx.split(",") if t.strip()]

    properties = _canned_properties(idx)
    for name in names:
        properties = merge_properties(properties, index_properties(name))

    return {
        index: {
            "mappings": {
                "properties": properties,
            },
        },
    }


def _canned_properties(index: str) -> dict:
    """The fields mockdr's own collections carry, by index pattern."""
    names = [t.strip() for t in index.lower().split(",") if t.strip()]
    if any(_pattern_hits(n, _ALERT_PREFIXES) for n in names):
        return {
            "@timestamp": {"type": "date"},
            "signal.rule.id": {"type": "keyword"},
            "signal.rule.name": {"type": "keyword"},
            "signal.status": {"type": "keyword"},
            "kibana.alert.severity": {"type": "keyword"},
            "kibana.alert.workflow_status": {"type": "keyword"},
            "agent.id": {"type": "keyword"},
            "host.name": {"type": "keyword"},
        }
    if any(_pattern_hits(n, _ENDPOINT_PREFIXES) for n in names):
        return {
            "@timestamp": {"type": "date"},
            "agent.id": {"type": "keyword"},
            "agent.status": {"type": "keyword"},
            "host.hostname": {"type": "keyword"},
            "host.os.name": {"type": "keyword"},
            "host.os.platform": {"type": "keyword"},
            "host.ip": {"type": "ip"},
        }
    return {}


def es_get_stats(index: str, *, ignore_unavailable: bool = False) -> dict:
    """Return canned index stats for known index patterns.

    Args:
        index:              Target index name or pattern.
        ignore_unavailable: Skip a missing concrete index instead of failing.

    Returns:
        Elasticsearch index stats response dict.
    """
    records, _, _written = _resolve_collection(index, ignore_unavailable=ignore_unavailable)
    doc_count = len(records)

    return {
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "_all": {
            "primaries": {
                "docs": {"count": doc_count, "deleted": 0},
                "store": {"size_in_bytes": doc_count * 1024},
            },
            "total": {
                "docs": {"count": doc_count, "deleted": 0},
                "store": {"size_in_bytes": doc_count * 1024},
            },
        },
        "indices": {
            index: {
                "primaries": {
                    "docs": {"count": doc_count, "deleted": 0},
                    "store": {"size_in_bytes": doc_count * 1024},
                },
                "total": {
                    "docs": {"count": doc_count, "deleted": 0},
                    "store": {"size_in_bytes": doc_count * 1024},
                },
            },
        },
    }


def cluster_info() -> dict:
    """Return mock Elasticsearch cluster info (version 8.x).

    Returns:
        Elasticsearch cluster info response dict.
    """
    return {
        "name": "mock-es-node-01",
        "cluster_name": "mockdr-elastic",
        "cluster_uuid": "mock-cluster-uuid-0001",
        "version": {
            "number": "8.12.0",
            "build_flavor": "default",
            "build_type": "docker",
            "build_hash": "abc123mock",
            "build_date": "2024-01-01T00:00:00.000Z",
            "build_snapshot": False,
            "lucene_version": "9.9.1",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }
