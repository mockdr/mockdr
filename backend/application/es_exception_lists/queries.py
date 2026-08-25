"""Elastic Security Exception Lists query handlers (read-only)."""
from __future__ import annotations

from repository.es_exception_item_repo import es_exception_item_repo
from repository.es_exception_list_repo import es_exception_list_repo
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_list_response
from utils.serde import record_dict


def find_lists(
    list_id: str | None = None,
    namespace_type: str | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict:
    """Find exception lists with optional filters and Kibana pagination.

    Args:
        list_id:        Filter by list_id.
        namespace_type: Filter by namespace_type (single or agnostic).
        page:           Page number (1-based).
        per_page:       Number of items per page.

    Returns:
        Kibana paginated list response.
    """
    records = [_serialise(el) for el in es_exception_list_repo.list_all()]

    if list_id:
        records = [r for r in records if r["list_id"] == list_id]
    if namespace_type:
        records = [r for r in records if r["namespace_type"] == namespace_type]

    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_list_response(page_items, page, per_page, total)


def get_list(list_id_or_id: str) -> dict | None:
    """Get a single exception list by its list_id or internal id.

    Args:
        list_id_or_id: The list_id or UUID of the exception list.

    Returns:
        Exception list dict, or None if not found.
    """
    # Try by internal id first.
    el = es_exception_list_repo.get(list_id_or_id)
    if el:
        return _serialise(el)

    # Fall back to list_id.
    el = es_exception_list_repo.get_by_list_id(list_id_or_id)
    if el:
        return _serialise(el)

    return None


def _serialise(record: object) -> dict:
    """Render a list the way Kibana does — a `meta` it has no value for is absent.

    Emitting `meta: null` told a client the member exists and is empty, where
    a real list simply has no such member until one is set.
    """
    rendered = record_dict(record)
    if rendered.get("meta") is None:
        rendered.pop("meta", None)
    return rendered


class ExceptionListNotFoundError(LookupError):
    """Raised when a query names an exception list that is not there.

    Kibana answers it in the Security Solution's envelope —
    ``{"message": ..., "status_code": 404}`` — rather than Boom's.
    """

    def __init__(self, list_id: str) -> None:
        """Record the list id, which the message quotes."""
        self.list_id = list_id
        super().__init__(f'exception list id: "{list_id}" does not exist')


def find_items(
    list_id: str | None = None,
    namespace_type: str | None = None,
    tags: list[str] | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict:
    """Find exception items with optional filters and Kibana pagination.

    Args:
        list_id:        Filter by parent list_id.
        namespace_type: Filter by namespace_type.
        tags:           Filter by tags — item must contain at least one matching tag.
        page:           Page number (1-based).
        per_page:       Number of items per page.

    Returns:
        Kibana paginated list response.
    """
    records = [record_dict(i) for i in es_exception_item_repo.list_all()]

    if list_id:
        # A list that is not there is a 404, not an empty page: a client
        # searching the wrong list was told it exists and holds nothing.
        if not any(
            record_dict(one).get("list_id") == list_id
            for one in es_exception_list_repo.list_all()
        ):
            raise ExceptionListNotFoundError(list_id)
        records = [r for r in records if r["list_id"] == list_id]
    if namespace_type:
        records = [r for r in records if r["namespace_type"] == namespace_type]
    if tags:
        tag_set = set(tags)
        records = [r for r in records if tag_set & set(r.get("tags", []))]

    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_list_response(page_items, page, per_page, total)


def get_item(item_id_or_id: str) -> dict | None:
    """Get a single exception item by its item_id or internal id.

    Args:
        item_id_or_id: The item_id or UUID of the exception item.

    Returns:
        Exception item dict, or None if not found.
    """
    # Try by internal id first.
    item = es_exception_item_repo.get(item_id_or_id)
    if item:
        return record_dict(item)

    # Fall back to item_id.
    for i in es_exception_item_repo.list_all():
        if i.item_id == item_id_or_id:
            return record_dict(i)

    return None
