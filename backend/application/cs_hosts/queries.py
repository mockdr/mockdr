"""CrowdStrike Falcon Host query handlers (read-only)."""
from __future__ import annotations

from repository.cs_host_repo import cs_host_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import (
    build_cs_entity_response,
    build_cs_id_response,
    build_cs_list_response,
)
from utils.dt import seconds_since
from utils.internal_fields import CS_HOST_INTERNAL_FIELDS
from utils.nested import get_nested
from utils.serde import record_dict
from utils.strip import strip_fields


def _visible_hosts(*, hidden: bool = False) -> list:
    """The hosts a listing shows.

    A hidden host is kept but not listed — Falcon serves it from
    ``/devices/combined/devices-hidden/v1`` instead, which is the only place
    it appears until it is restored.
    """
    return [h for h in cs_host_repo.list_all() if bool(getattr(h, "hidden", False)) is hidden]


#: What a pending state settles into once the sensor has acknowledged it.
#: Without this a contained host stayed `containment_pending` for ever, so a
#: playbook that contains a host and polls until `contained` never finished —
#: and `lift_containment` skipped its own pending state entirely, which the
#: fleet is seeded with.
_SETTLES_INTO = {
    "containment_pending": "contained",
    "lift_containment_pending": "normal",
}

#: How long the sensor takes to acknowledge, so a client that polls twice
#: sees the state move rather than finding it already done.
_SETTLE_SECONDS = 1.0


def _settled(host: object) -> object:
    """Move a host out of a pending containment state once the wait is over."""
    settled = _SETTLES_INTO.get(str(getattr(host, "status", "")))
    if settled is None:
        return host
    waited = seconds_since(str(getattr(host, "modified_timestamp", "") or ""))
    if waited is None or waited <= _SETTLE_SECONDS:
        return host
    host.status = settled  # type: ignore[attr-defined]
    cs_host_repo.save(host)  # type: ignore[arg-type]
    return host


def _public(host: object) -> dict:
    """One host as Falcon serves it, without mockdr's own bookkeeping."""
    return strip_fields(record_dict(_settled(host)), CS_HOST_INTERNAL_FIELDS)


def _parse_sort(sort: str | None) -> tuple[str, bool]:
    """Parse a CrowdStrike sort string into field name and direction.

    Args:
        sort: Sort string in ``field.asc`` or ``field.desc`` format, or None.

    Returns:
        Tuple of ``(field_name, descending)`` with sensible defaults.
    """
    if not sort:
        return "last_seen", True
    parts = sort.rsplit(".", 1)
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return field_name, desc


def query_host_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query host IDs matching FQL filter.

    Returns a CrowdStrike ID response with pagination metadata.

    Args:
        filter_fql: FQL filter string, or None for all hosts.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope.
    """
    records = _visible_hosts()
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: get_nested(r, field_name) or "", reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [get_nested(r, "device_id") for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_host_entities(ids: list[str]) -> dict:
    """Get full host entities by device_id list.

    Args:
        ids: List of device IDs to retrieve.

    Returns:
        CS entity response envelope containing full host dicts.
    """
    entities: list[dict] = []
    for device_id in ids:
        host = cs_host_repo.get(device_id)
        # A hidden host is gone as far as this endpoint is concerned; Falcon
        # serves it from `devices-hidden` until it is restored.
        if host and not getattr(host, "hidden", False):
            entities.append(_public(host))
    return build_cs_entity_response(entities)


def query_host_ids_scroll(
    filter_fql: str | None,
    offset: str | None,
    limit: int,
    sort: str | None,
) -> dict:
    """Query host IDs with scroll-based pagination.

    Uses a string offset cursor (index encoded as string) matching
    FalconPy's ``query_devices_by_filter_scroll()`` contract.

    Args:
        filter_fql: FQL filter string, or None for all hosts.
        offset:     Scroll cursor (stringified integer index), or None/empty.
        limit:      Maximum number of IDs to return per page.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response with scroll-style pagination metadata.
    """
    records = _visible_hosts()
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: get_nested(r, field_name) or "", reverse=desc)
    total = len(records)

    start = int(offset) if offset else 0
    page = records[start : start + limit]
    ids = [get_nested(r, "device_id") for r in page]

    next_offset = "" if start + limit >= total else str(start + limit)

    return {
        "meta": {
            "query_time": 0.01,
            "powered_by": "device-api",
            "trace_id": build_cs_id_response([], 0)["meta"]["trace_id"],
            "pagination": {
                "offset": next_offset,
                "limit": limit,
                "total": total if start == 0 else 0,
            },
        },
        "resources": ids,
        "errors": [],
    }


def list_hidden_hosts(filter_fql: str | None, offset: int, limit: int,
                      sort: str | None) -> dict:
    """The hosts that `hide_host` has taken out of the listings.

    Falcon publishes them at ``/devices/combined/devices-hidden/v1``, which
    is the only place a hidden host appears — and the reason hiding has to
    keep the record rather than drop it.

    Args:
        filter_fql: FQL filter string, or None for all hidden hosts.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of hosts to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS list response envelope with full host entities.
    """
    page, total = _hidden_page(filter_fql, offset, limit, sort)
    return build_cs_list_response([_public(h) for h in page], total, offset, limit)


def query_hidden_host_ids(filter_fql: str | None, offset: int, limit: int,
                          sort: str | None) -> dict:
    """The ids of the hosts `hide_host` has taken out of the listings.

    Falcon publishes hidden hosts twice, as it does every collection: the
    documents at `/devices/combined/devices-hidden/v1` and the ids at
    `/devices/queries/devices-hidden/v1`. Only the first was served, so a
    client following the ids-then-entities pattern — which is how Falcon's
    own SDK reads a collection — got a 404 from the half it starts with.

    Args:
        filter_fql: FQL filter string, or None for all hidden hosts.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of ids to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope with the hidden hosts' device ids.
    """
    from utils.cs_response import build_cs_id_response  # noqa: PLC0415

    page, total = _hidden_page(filter_fql, offset, limit, sort)
    return build_cs_id_response(
        [str(get_nested(h, "device_id")) for h in page], total, offset, limit,
    )


def _hidden_page(filter_fql: str | None, offset: int, limit: int,
                 sort: str | None) -> tuple[list[dict], int]:
    """One page of hidden hosts, filtered and sorted, and how many there are."""
    records = _visible_hosts(hidden=True)
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: get_nested(r, field_name) or "", reverse=desc)
    return paginate_cs(records, offset, limit)
