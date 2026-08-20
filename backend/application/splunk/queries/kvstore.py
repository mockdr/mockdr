"""Splunk KV Store query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.kv_collection_repo import kv_collection_repo
from utils.splunk.kvstore_query import apply_fields, apply_query, apply_sort
from utils.splunk.response import build_splunk_entry, build_splunk_envelope


def list_collections(app: str = "search") -> dict:
    """Return all KV Store collections in Splunk envelope format."""
    all_colls = kv_collection_repo.list_all()
    colls = [c for c in all_colls if c.app == app]
    entries = []
    for coll in colls:
        content = {
            "field.types": coll.field_types,
            "accelerated_fields": coll.accelerated_fields,
        }
        entries.append(build_splunk_entry(
            coll.name, content, collection="storage/collections/config",
        ))
    return build_splunk_envelope(entries)


def collection_exists(name: str, app: str = "search") -> bool:
    """Whether a KV collection exists.

    A read of a missing collection returned ``200 []``, which a client cannot
    tell apart from an empty one; real Splunk answers 404.
    """
    return kv_collection_repo.get_by_name(name, app) is not None


def get_records(
    name: str,
    app: str = "search",
    *,
    query: str = "",
    fields: str = "",
    sort: str = "",
    limit: int = 0,
    skip: int = 0,
) -> list[dict]:
    """Return records in a KV collection, filtered and paged as requested.

    Args:
        name:   Collection name.
        app:    Splunk app context.
        query:  JSON query object, supporting ``$gt``/``$gte``/``$lt``/
                ``$lte``/``$ne``/``$in``/``$regex``/``$and``/``$or``.
        fields: Comma-separated projection, ``name:0`` to exclude.
        sort:   Comma-separated sort fields, ``-name`` for descending.
        limit:  Maximum records to return; ``0`` means all.
        skip:   Records to skip.

    Returns:
        The matching records.
    """
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return []

    records = apply_query(coll.records, query)
    records = apply_sort(records, sort)
    if skip:
        records = records[skip:]
    if limit > 0:
        records = records[:limit]
    return apply_fields(records, fields)


def get_record(name: str, key: str, app: str = "search") -> dict | None:
    """Return a single record from a KV collection."""
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return None
    for r in coll.records:
        if r.get("_key") == key:
            return r
    return None
