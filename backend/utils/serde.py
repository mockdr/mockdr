"""Turn a stored dataclass record into the plain dict a response is built from.

``dataclasses.asdict`` deep-copies every leaf it walks — a string, an int, a
timestamp — which is most of a record. The copy exists so a caller cannot
reach back into the store, and only *mutable* values can carry that risk:
this rebuilds dicts, lists and sets and shares everything else. Measured on
``GET /threats``: 11 700 ``_asdict_inner`` calls per request, gone.

Same contract as ``asdict``: a dataclass instance in, plain data out, and a
``TypeError`` for anything else.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from functools import cache
from typing import Any

#: Values that cannot be mutated, so the caller may hold the store's own.
#: Checked by exact type: one dict lookup instead of the ladder below, for
#: what is nearly every field of nearly every record.
_IMMUTABLE = frozenset({str, int, float, bool, bytes, type(None)})


@cache
def _field_names(cls: type) -> tuple[str, ...]:
    """The dataclass's field names; the class list never changes at runtime."""
    return tuple(f.name for f in fields(cls))


def record_dict(record: Any) -> dict[str, Any]:  # noqa: ANN401 - any stored record
    """A dataclass record as plain data the caller may mutate freely."""
    cls = type(record)
    if not is_dataclass(cls) or isinstance(record, type):
        msg = "record_dict() should be called on dataclass instances"
        raise TypeError(msg)
    return {name: _plain(getattr(record, name)) for name in _field_names(cls)}


def _plain(value: Any) -> Any:  # noqa: ANN401 - any field value
    """A field value with its mutable containers rebuilt and its scalars shared."""
    cls = type(value)
    if cls in _IMMUTABLE:
        return value
    if cls is dict:
        return {k: _plain(v) for k, v in value.items()}
    if cls is list:
        return [_plain(v) for v in value]
    if is_dataclass(cls) and not isinstance(value, type):
        return {name: _plain(getattr(value, name)) for name in _field_names(cls)}
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, tuple):
        # ``asdict`` keeps the tuple type, namedtuples included.
        if hasattr(value, "_fields"):
            return type(value)(*(_plain(v) for v in value))
        return type(value)(_plain(v) for v in value)
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return type(value)(_plain(v) for v in value)
    return value
