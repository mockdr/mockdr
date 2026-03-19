"""Splunk KV Store query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.kv_collection_repo import kv_collection_repo
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
        entries.append(build_splunk_entry(coll.name, content))
    return build_splunk_envelope(entries)


def get_records(name: str, app: str = "search") -> list[dict]:
    """Return all records in a KV collection."""
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return []
    return coll.records


def get_record(name: str, key: str, app: str = "search") -> dict | None:
    """Return a single record from a KV collection."""
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return None
    for r in coll.records:
        if r.get("_key") == key:
            return r
    return None
