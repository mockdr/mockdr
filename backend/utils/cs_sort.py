"""CrowdStrike Falcon ``sort`` parameter parsing.

Falcon spells a sort two ways, and documents both:

* ``field|direction`` — gofalcon's alerts ``QueryV2`` ("Sort parameter
  takes the form <field|direction> ... For example: `status|asc`"), cases
  (``queries_cases_get_v1_parameters.go``), quarantine ("Ex:
  'date_created|asc'") and users (``Default: "uid|asc"``); falconpy's
  scrolling discussion #536 sorts hosts with ``hostname|asc``.
* ``field.direction`` — the hosts queries ("e.g. status.desc or
  hostname.asc", ``query_devices_by_filter_parameters.go``) and falconpy's
  ``sensor_versions_by_hostname_scrolling.py`` sample (``hostname.asc``).

Every parser on this mount split on the last ``.`` only, so the pipe form
— the one alerts, cases, quarantine and users document — was read as a
field named ``status|asc`` that no record has, and the answer came back in
storage order with a 200. And a dotted field with no direction
(``metadata.av_hits``, ``device.hostname``, both in Falcon's sort
vocabularies) lost its last segment as a "direction".

Both forms are accepted on every route: a client that sends the dot form
where Falcon documents the pipe one (or the reverse) has always been served
here, and nothing measured says Falcon refuses it.
"""
from __future__ import annotations

_DIRECTIONS = ("asc", "desc")


def parse_cs_sort(
    sort: str | None, default_field: str, default_desc: bool,
) -> tuple[str, bool]:
    """Split a Falcon sort into ``(field, descending)``.

    Args:
        sort:          ``field|asc``, ``field.desc``, a bare ``field``, or
                       None for the route's default order.
        default_field: The field a route sorts by when no sort is given.
        default_desc:  Whether that default order is descending.

    Returns:
        The field path (dots kept for nested fields) and whether the order
        is descending. A bare field sorts ascending.
    """
    text = (sort or "").strip()
    if not text:
        return default_field, default_desc
    if "|" in text:
        field_name, _, direction = text.rpartition("|")
        return field_name.strip(), direction.strip().lower() == "desc"
    head, dot, tail = text.rpartition(".")
    if dot and tail.lower() in _DIRECTIONS:
        return head, tail.lower() == "desc"
    return text, False


def sort_key(value: object) -> tuple[int, float, str]:
    """A key that orders one field's values without comparing across types.

    A missing value sorts first, then numbers by value, then everything
    else by its text — so a field that is a number on one record and absent
    on the next does not raise ``TypeError`` out of ``list.sort``.
    """
    if value is None:
        return (0, 0.0, "")
    if isinstance(value, (int, float)):
        return (1, float(value), "")
    return (2, 0.0, str(value))
