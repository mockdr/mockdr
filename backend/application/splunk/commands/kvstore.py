"""Splunk KV Store command handlers."""
from __future__ import annotations

import uuid

from domain.splunk.kv_collection import KVCollection
from repository.splunk.kv_collection_repo import kv_collection_repo


def create_collection(
    name: str,
    app: str = "search",
    owner: str = "nobody",
    field_types: dict[str, str] | None = None,
) -> KVCollection:
    """Create a new KV Store collection.

    Args:
        name:        Collection name.
        app:         Splunk app context.
        owner:       Collection owner.
        field_types: Optional field type definitions.

    Returns:
        The created KVCollection.
    """
    coll = KVCollection(
        name=name,
        app=app,
        owner=owner,
        field_types=field_types or {},
    )
    kv_collection_repo.save(coll)
    return coll


def delete_collection(name: str, app: str = "search") -> bool:
    """Delete a KV Store collection.

    Args:
        name: Collection name.
        app:  Splunk app context.

    Returns:
        True if found and deleted.
    """
    key = f"{app}/{name}"
    return kv_collection_repo.delete(key)


def insert_record(
    name: str,
    record: dict,
    app: str = "search",
) -> dict:
    """Insert a record into a KV collection.

    Args:
        name:   Collection name.
        record: Record data.
        app:    Splunk app context.

    Returns:
        The inserted record with ``_key``.
    """
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return {}

    if "_key" not in record:
        record["_key"] = str(uuid.uuid4())

    coll.records.append(record)
    kv_collection_repo.save(coll)
    return record


def update_record(
    name: str,
    key: str,
    record: dict,
    app: str = "search",
) -> dict | None:
    """Update a record in a KV collection.

    Args:
        name:   Collection name.
        key:    Record _key.
        record: Updated record data.
        app:    Splunk app context.

    Returns:
        The updated record, or None if not found.
    """
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return None

    for i, r in enumerate(coll.records):
        if r.get("_key") == key:
            record["_key"] = key
            coll.records[i] = record
            kv_collection_repo.save(coll)
            return record
    return None


def delete_record(name: str, key: str, app: str = "search") -> bool:
    """Delete a record from a KV collection.

    Args:
        name: Collection name.
        key:  Record _key.
        app:  Splunk app context.

    Returns:
        True if found and deleted.
    """
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return False

    original_len = len(coll.records)
    coll.records = [r for r in coll.records if r.get("_key") != key]
    if len(coll.records) < original_len:
        kv_collection_repo.save(coll)
        return True
    return False


def delete_all_records(name: str, app: str = "search", query: str = "") -> bool:
    """Delete all records (optionally matching a query) from a KV collection.

    Args:
        name:  Collection name.
        app:   Splunk app context.
        query: Optional JSON query filter (not fully implemented).

    Returns:
        True if collection found.
    """
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return False

    coll.records.clear()
    kv_collection_repo.save(coll)
    return True


def batch_save(
    name: str,
    records: list[dict],
    app: str = "search",
) -> list[dict]:
    """Batch upsert records into a KV collection.

    Args:
        name:    Collection name.
        records: List of records to upsert.
        app:     Splunk app context.

    Returns:
        List of upserted records with ``_key``.
    """
    coll = kv_collection_repo.get_by_name(name, app)
    if not coll:
        return []

    result = []
    for record in records:
        key = record.get("_key", str(uuid.uuid4()))
        record["_key"] = key

        # Upsert: update if exists, insert if not
        found = False
        for i, r in enumerate(coll.records):
            if r.get("_key") == key:
                coll.records[i] = record
                found = True
                break
        if not found:
            coll.records.append(record)
        result.append(record)

    kv_collection_repo.save(coll)
    return result
