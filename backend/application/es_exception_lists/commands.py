"""Elastic Security Exception Lists command handlers (mutations)."""
from __future__ import annotations

import uuid
from dataclasses import asdict

from domain.es_exception_item import EsExceptionItem
from domain.es_exception_list import EsExceptionList
from repository.es_exception_item_repo import es_exception_item_repo
from repository.es_exception_list_repo import es_exception_list_repo
from utils.dt import utc_now

# ── Exception Lists ──────────────────────────────────────────────────────────


def create_list(data: dict) -> dict:
    """Create a new exception list.

    Args:
        data: Request body with name, description, list_id, type, etc.

    Returns:
        The newly created exception list as a dict.
    """
    now = utc_now()
    el = EsExceptionList(
        id=str(uuid.uuid4()),
        list_id=data.get("list_id", str(uuid.uuid4())),
        name=data.get("name", ""),
        description=data.get("description", ""),
        type=data.get("type", "detection"),
        namespace_type=data.get("namespace_type", "single"),
        tags=data.get("tags", []),
        os_types=data.get("os_types", []),
        created_at=now,
        created_by=data.get("created_by", "elastic"),
        updated_at=now,
        updated_by=data.get("created_by", "elastic"),
    )
    es_exception_list_repo.save(el)
    return asdict(el)


def update_list(data: dict) -> dict | None:
    """Update an existing exception list.

    Args:
        data: Request body with id or list_id, plus fields to update.

    Returns:
        Updated exception list dict, or None if not found.
    """
    # Resolve by id or list_id.
    el = None
    if "id" in data:
        el = es_exception_list_repo.get(data["id"])
    if not el and "list_id" in data:
        el = es_exception_list_repo.get_by_list_id(data["list_id"])
    if not el:
        return None

    now = utc_now()
    updatable = ("name", "description", "tags", "os_types", "type")
    for field in updatable:
        if field in data:
            setattr(el, field, data[field])

    el.updated_at = now
    el.updated_by = data.get("updated_by", "elastic")
    el.version += 1

    es_exception_list_repo.save(el)
    return asdict(el)


def delete_list(list_id: str) -> bool:
    """Delete an exception list and all its items.

    Args:
        list_id: The list_id of the exception list to delete.

    Returns:
        True if the list existed and was deleted, False otherwise.
    """
    el = es_exception_list_repo.get_by_list_id(list_id)
    if not el:
        # Try by internal id.
        el = es_exception_list_repo.get(list_id)
    if not el:
        return False

    # Remove all items belonging to this list.
    for item in es_exception_item_repo.get_by_list_id(el.list_id):
        es_exception_item_repo.delete(item.id)

    return es_exception_list_repo.delete(el.id)


# ── Exception Items ──────────────────────────────────────────────────────────


def create_item(data: dict) -> dict:
    """Create a new exception item.

    Args:
        data: Request body with name, list_id, entries, etc.

    Returns:
        The newly created exception item as a dict.
    """
    now = utc_now()
    item = EsExceptionItem(
        id=str(uuid.uuid4()),
        item_id=data.get("item_id", str(uuid.uuid4())),
        list_id=data.get("list_id", ""),
        name=data.get("name", ""),
        description=data.get("description", ""),
        type=data.get("type", "simple"),
        namespace_type=data.get("namespace_type", "single"),
        entries=data.get("entries", []),
        os_types=data.get("os_types", []),
        tags=data.get("tags", []),
        created_at=now,
        created_by=data.get("created_by", "elastic"),
        updated_at=now,
        updated_by=data.get("created_by", "elastic"),
    )
    es_exception_item_repo.save(item)
    return asdict(item)


def update_item(data: dict) -> dict | None:
    """Update an existing exception item.

    Args:
        data: Request body with id or item_id, plus fields to update.

    Returns:
        Updated exception item dict, or None if not found.
    """
    # Resolve by id or item_id.
    item = None
    if "id" in data:
        item = es_exception_item_repo.get(data["id"])
    if not item and "item_id" in data:
        for i in es_exception_item_repo.list_all():
            if i.item_id == data["item_id"]:
                item = i
                break
    if not item:
        return None

    now = utc_now()
    updatable = ("name", "description", "entries", "os_types", "tags", "type")
    for field in updatable:
        if field in data:
            setattr(item, field, data[field])

    item.updated_at = now
    item.updated_by = data.get("updated_by", "elastic")

    es_exception_item_repo.save(item)
    return asdict(item)


def delete_item(item_id: str) -> bool:
    """Delete an exception item.

    Args:
        item_id: The item_id or internal id of the exception item to delete.

    Returns:
        True if the item existed and was deleted, False otherwise.
    """
    # Try by internal id first.
    if es_exception_item_repo.exists(item_id):
        return es_exception_item_repo.delete(item_id)

    # Fall back to item_id.
    for i in es_exception_item_repo.list_all():
        if i.item_id == item_id:
            return es_exception_item_repo.delete(i.id)

    return False
