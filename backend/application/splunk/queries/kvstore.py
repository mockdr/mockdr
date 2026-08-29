"""Splunk KV Store query handlers (read-only)."""

from __future__ import annotations

import json

from repository.splunk.kv_collection_repo import kv_collection_repo
from utils.splunk.kvstore_query import apply_fields, apply_query, apply_sort
from utils.splunk.response import (
    build_splunk_entry,
    build_splunk_envelope,
    complete,
    fixture_top_links,
)

#: A KV collection's ACL carries the four sharing capabilities (10.4.2).
_KV_ACL = {
    "can_change_perms": True,
    "can_share_app": True,
    "can_share_global": True,
    "can_share_user": False,
}


def get_collection_config(name: str, app: str | None = "search") -> dict | None:
    """One collection's configuration, addressed by name.

    splunkd serves the entry under its own path as well as in the listing,
    and mockdr had only the listing — so a client reading back the
    collection it had just created met the catch-all's 400 about a missing
    target name, where splunkd answers the entry or a 404 naming it.
    """
    listing = list_collections(app)
    entries = [e for e in listing.get("entry", []) if e.get("name") == name]
    if not entries:
        return None
    # A single read names what the collection accepts; the listing does not.
    # The wildcards are the two families a schema is written in — measured on
    # 10.4.2, and the first `fields` block here with a non-empty one.
    entry = {**entries[0], "fields": {
        "required": [],
        "optional": [
            "enforceTypes", "profilingEnabled", "profilingThresholdMs",
            "replicate", "replication_dump_maximum_file_size",
            "replication_dump_strategy",
        ],
        "wildcard": ["accelerated_fields\\..*", "field\\..*"],
    }}
    return {**listing, "entry": [entry], "paging": {
        **(listing.get("paging") or {}), "total": 1,
    }}


def list_collections(app: str | None = "search") -> dict:
    """Return the KV Store collections in Splunk envelope format.

    ``app=None`` is the app-less ``/services`` namespace, which on splunkd
    lists every app's collections.
    """
    all_colls = kv_collection_repo.list_all()
    colls = [c for c in all_colls if app is None or c.app == app]
    entries = []
    for coll in colls:
        # splunkd flattens the collection schema into dotted keys:
        # ``field.<name>: <type>`` and ``accelerated_fields.<name>: <json>``.
        content: dict = {f"field.{k}": v for k, v in (coll.field_types or {}).items()}
        for k, v in (coll.accelerated_fields or {}).items():
            content[f"accelerated_fields.{k}"] = v if isinstance(v, str) else json.dumps(v)
        entries.append(
            build_splunk_entry(
                coll.name,
                complete(content, "kv_config"),
                collection="storage/collections/config",
                links=("_reload", "alternate", "disable", "edit", "list"),
                fields=False,
                acl_extra=_KV_ACL,
            )
        )
    return build_splunk_envelope(entries, links=fixture_top_links("kv_config"))


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
