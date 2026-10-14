"""Which records a write's ``filter`` selects -- exactly what a GET would return.

SentinelOne's bulk writes (``/agents/actions/*``, ``DELETE /device-control``,
``PUT /groups/{id}/move-agents``, ...) name their targets with a ``filter``
object carrying the same members the collection's GET takes on its query
string. The agent actions resolved the whole filter through the list
endpoint's engine; other writes read ``ids`` and nothing else, so a body
scoped by ``siteIds`` or ``name__contains`` selected nobody (or was refused
for want of ``ids``) while the same filter on the GET answered rows.

:func:`select_ids` is the agent actions' resolution, shared: ``ids`` names
the records outright, every other member goes through
:func:`utils.filtering.apply_filters` with the route's specs, and a member
the route cannot select on is refused rather than ignored -- ``apply_filters``
answers every record when no spec applies, and a delete scoped by a typo
would otherwise delete everything.
"""
from __future__ import annotations

from collections.abc import Iterable

from utils.filtering import FilterSpec, apply_filters
from utils.serde import record_dict


class UnselectableFilterError(ValueError):
    """The filter names a member this route cannot select on."""


def select_ids(
    records: Iterable[object],
    raw_filter: dict,
    specs: list[FilterSpec],
    *,
    id_field: str = "id",
    ids_members: tuple[str, ...] = ("ids",),
) -> list[str]:
    """The ids of the records *raw_filter* selects.

    Args:
        records:     The collection's records (domain objects or dicts).
        raw_filter:  The body's ``filter`` object; callers refuse an empty one
                     in their own words before calling.
        specs:       The filter specs the collection's GET applies.
        id_field:    The record field the ids name.
        ids_members: The members that name records outright.

    Returns:
        The selected ids; a member in *ids_members* wins over the rest.

    Raises:
        UnselectableFilterError: A member the specs do not know.
    """
    for member in ids_members:
        if raw_filter.get(member):
            return list(raw_filter[member])
    params = {k: v for k, v in raw_filter.items() if v is not None}
    known = {spec.param for spec in specs} | set(ids_members)
    unknown = sorted(set(params) - known)
    if unknown:
        msg = (
            f"The filter names {'members' if len(unknown) > 1 else 'a member'} "
            f"this endpoint cannot select on: {', '.join(unknown)}."
        )
        raise UnselectableFilterError(msg)
    rows = [r if isinstance(r, dict) else record_dict(r) for r in records]
    return [str(r.get(id_field)) for r in apply_filters(rows, params, specs)]
