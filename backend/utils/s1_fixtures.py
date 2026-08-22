"""Complete SentinelOne responses to the shape the Management API 2.1 swagger declares.

The swagger is generated from the product's own response schemas, so every
property it declares is one a real response carries. ``scripts/gen_s1_fixtures.py``
writes a type-correct default object per response definition to
``infrastructure/fixtures/sentinelone/``; the builders deep-merge their values
over it, so a client reading any declared field finds it.
"""

from __future__ import annotations

import copy
import json
from functools import cache
from pathlib import Path

_FIXTURES = Path(__file__).resolve().parents[1] / "infrastructure" / "fixtures" / "sentinelone"


@cache
def _fixture(definition: str) -> dict:
    path = _FIXTURES / f"{definition}.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def deep_complete(defaults: dict, actual: dict) -> dict:
    """``actual`` with every key of ``defaults`` it lacks filled in, recursively."""
    # A list in the defaults is a template for items the record provides;
    # a record without the list gets [] — never a one-item list of blanks.
    out = {k: ([] if isinstance(v, list) else copy.deepcopy(v)) for k, v in defaults.items()}
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
        elif value is None and isinstance(template, (dict, list)):
            # The product answers an object of nulls, not a null object
            # (``containerInfo: {"id": null, …}``), so keep the declared shape.
            out[key] = template
        else:
            out[key] = value
    return out


def complete_item(item: dict, definition: str) -> dict:
    """One ``data`` item (or the single ``data`` object) completed to ``definition``."""
    data = _fixture(definition).get("data")
    template = data[0] if isinstance(data, list) and data else data
    if not isinstance(template, dict):
        return item
    return deep_complete(template, item)


def complete_s1(payload: dict, definition: str) -> dict:
    """A whole ``{"data": …}`` response completed to ``definition``."""
    data = payload.get("data")
    if isinstance(data, list):
        return {
            **payload,
            "data": [complete_item(i, definition) if isinstance(i, dict) else i for i in data],
        }
    if isinstance(data, dict):
        return {**payload, "data": complete_item(data, definition)}
    return payload


def restrict_item(item: dict, definition: str) -> dict:
    """``item`` completed to ``definition`` and reduced to the fields it declares."""
    data = _fixture(definition).get("data")
    template = data[0] if isinstance(data, list) and data else data
    if not isinstance(template, dict):
        return item
    return {k: v for k, v in deep_complete(template, item).items() if k in template}


def restrict_s1(payload: dict, definition: str) -> dict:
    """A whole ``{"data": …}`` response reduced to the fields ``definition`` declares."""
    data = payload.get("data")
    if isinstance(data, list):
        return {
            **payload,
            "data": [restrict_item(i, definition) if isinstance(i, dict) else i for i in data],
        }
    if isinstance(data, dict):
        return {**payload, "data": restrict_item(data, definition)}
    return payload
