# ruff: noqa: ANN401
"""Complete Cortex XDR replies to the shape recorded from the real product.

``scripts/gen_xdr_fixtures.py`` derives one default ``reply`` per route from
the XSOAR pack's recorded responses; the handlers deep-merge their data over
it, so every field a real reply carries is present. List items are completed
against the fixture's template item.
"""

from __future__ import annotations

import copy
import functools
import inspect
import json
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

_FIXTURES = Path(__file__).resolve().parents[1] / "infrastructure" / "fixtures" / "xdr"


@cache
def _fixture(slug: str) -> dict:
    path = _FIXTURES / f"{slug}.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("reply", {}) if isinstance(data, dict) else {}  # dict or list template


def deep_complete(defaults: Any, actual: Any) -> Any:
    """``actual`` completed against ``defaults``; a list against its template item."""
    if isinstance(defaults, dict) and isinstance(actual, dict):
        # A list in the defaults is a template for items the reply provides;
        # a reply without the list gets [] — never a one-item list of blanks.
        out = {k: ([] if isinstance(v, list) else copy.deepcopy(v)) for k, v in defaults.items()}
        for key, value in actual.items():
            out[key] = deep_complete(defaults.get(key), value) if key in defaults else value
        return out
    if isinstance(defaults, list) and isinstance(actual, list) and defaults:
        template = defaults[0]
        return [
            deep_complete(template, item) if isinstance(item, dict) else item for item in actual
        ]
    return actual


def complete_xdr(reply: Any, slug: str) -> Any:
    """The ``reply`` of route ``slug`` (``incidents_get_incidents``) completed."""
    defaults = _fixture(slug)
    return deep_complete(defaults, reply) if defaults and isinstance(reply, dict) else reply


def xdr_shape(slug: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a handler so its ``{"reply": …}`` is completed to the recorded shape."""

    def decorate(handler: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(handler):

            @functools.wraps(handler)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return _shaped(await handler(*args, **kwargs), slug)

            return async_wrapper

        @functools.wraps(handler)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return _shaped(handler(*args, **kwargs), slug)

        return wrapper

    return decorate


def _shaped(result: Any, slug: str) -> Any:
    """Complete a dict reply, or each item of a list reply, to the recorded shape."""
    if not isinstance(result, dict) or "reply" not in result:
        return result
    reply = result["reply"]
    defaults = _fixture(slug)
    if isinstance(reply, dict) and isinstance(defaults, dict):
        return {**result, "reply": deep_complete(defaults, reply)}
    if isinstance(reply, list) and isinstance(defaults, list) and defaults:
        return {
            **result,
            "reply": [deep_complete(defaults[0], i) if isinstance(i, dict) else i for i in reply],
        }
    return result


def complete_xdr_item(record: dict, slug: str, path: str) -> dict:
    """``record`` completed against the list template at ``path`` of route ``slug``.

    ``path`` walks the recorded reply to a list (``"incidents"``,
    ``"alerts.data"``); the list's first item is the template.
    """
    node: Any = _fixture(slug)
    for key in path.split("."):
        node = node.get(key, {}) if isinstance(node, dict) else {}
    template = node[0] if isinstance(node, list) and node and isinstance(node[0], dict) else {}
    return deep_complete(template, record) if template else record
