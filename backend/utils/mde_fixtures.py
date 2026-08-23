"""Complete Defender for Endpoint resources to the shape the docs declare.

``scripts/gen_mde_fixtures.py`` derives one default object per entity from
Microsoft's docs tree (property tables and response examples); the
serialisers deep-merge the stored record over it, so every documented field
is present.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

_FIXTURES = Path(__file__).resolve().parents[1] / "infrastructure" / "fixtures" / "mde"


@cache
def _fixture(entity: str) -> dict:
    path = _FIXTURES / f"{entity}.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _blank(default: object) -> object:
    """A fresh value for a key the record lacks: [] for a list, a rebuilt object, or the scalar."""
    if isinstance(default, list):
        return []
    if isinstance(default, dict):
        return {k: _blank(v) for k, v in default.items()}
    return default


def deep_complete(defaults: dict, actual: dict) -> dict:
    """``actual`` over ``defaults``; list items are completed against the template item."""
    # A list in the defaults is a template for items the record provides;
    # a record without the list gets [] — never a one-item list of blanks.
    # Scalars are immutable and shared; a nested object is rebuilt from its
    # template so the caller can mutate the result freely.
    out = {k: _blank(v) for k, v in defaults.items()}
    for key, value in actual.items():
        template = defaults.get(key)
        if isinstance(value, dict) and isinstance(template, dict):
            out[key] = deep_complete(template, value)
        elif (
            isinstance(value, list)
            and isinstance(template, list)
            and template
            and isinstance(template[0], dict)
        ):
            out[key] = [deep_complete(template[0], i) if isinstance(i, dict) else i for i in value]
        else:
            out[key] = value
    return out


def complete_mde(record: dict, entity: str) -> dict:
    """``record`` with every documented property of ``entity`` present."""
    defaults = _fixture(entity)
    return deep_complete(defaults, record) if defaults else record
