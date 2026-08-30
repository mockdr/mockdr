"""What each vendor says a resource of a route carries.

OData answers a query naming a property the type does not have with a `400`
— `Could not find a property named 'x'` — and mockdr answered `200`:
`$select` of an unknown name returned a page of empty objects, `$filter` on
one returned an empty collection, and `$orderby` on one sorted nothing while
reporting success. An empty answer is the shape of "nothing matched", so a
client with a typo in a property name read it as a quiet day.

Both tables are read from what is vendored under ``data/vendor-specs/``
rather than written here: Graph's from the reduced v1.0 reference, which
records the properties of the resource each route answers, and Defender's
from its docs' recorded response paths. A route neither of them speaks for
is not judged.
"""

from __future__ import annotations

import functools
import json
import re
from pathlib import Path

_SPECS = Path(__file__).resolve().parents[2] / "data" / "vendor-specs"

#: Where each reference's routes are mounted in this mock.
_GRAPH_PREFIX = "/graph"
_MDE_PREFIX = "/mde"

_FIRST_SEGMENT = re.compile(r"^[^.\[(/]+")


def _root(path: str) -> str:
    """The first segment of a recorded path: `evidence[*].x` -> `evidence`."""
    match = _FIRST_SEGMENT.match(path)
    return match.group(0) if match else ""


def _graph_properties() -> dict[str, frozenset[str]]:
    """Route -> the properties of the resource it answers, from the v1.0 reference."""
    path = _SPECS / "graph_v1.0_reduced.json"
    if not path.exists():
        return {}
    routes: dict[str, frozenset[str]] = {}
    for key, entry in json.loads(path.read_text()).items():
        if not key.startswith("GET /v1.0/") or not isinstance(entry, dict):
            continue
        names = {_root(p) for p in entry.get("item") or [] if not p.startswith("@odata")}
        names |= {_root(p) for p in entry.get("top") or [] if not p.startswith("@odata")}
        names.discard("")
        names.discard("value")
        if names:
            routes[_GRAPH_PREFIX + key[len("GET "):]] = frozenset(names)
    return routes


def _mde_properties() -> dict[str, frozenset[str]]:
    """Route -> the properties Defender's docs record for its answer."""
    path = _SPECS / "mde_docs_reduced.json"
    if not path.exists():
        return {}
    routes: dict[str, frozenset[str]] = {}

    def walk(node: object) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key.startswith("GET /api/") and isinstance(value, dict):
                names = {
                    _root(p[len("value[*]."):])
                    for p in value.get("paths") or []
                    if p.startswith("value[*].")
                }
                names.discard("")
                if names:
                    routes[_MDE_PREFIX + key[len("GET "):]] = frozenset(names)
            walk(value)

    reference = json.loads(path.read_text())
    walk(reference)

    # A route's recorded sample is a subset of what the entity carries: the
    # `machines` sample records 18 names while the docs' own `machine`
    # property table lists 21, `deviceValue` and `ipAddresses` among them. The
    # route's table alone refused `$filter=deviceValue eq 'Normal'` with
    # "Could not find a property named 'deviceValue'" on a route that answers
    # exactly that property.
    entities = reference.get("entities")
    if isinstance(entities, dict):
        for route, names in list(routes.items()):
            entity = _entity_of(route, entities)
            if entity:
                routes[route] = names | frozenset(entities[entity])
    return routes


def _entity_of(route: str, entities: dict) -> str:
    """The docs entity a route answers, by its last path segment.

    `/mde/api/machines` -> `machine`, `/mde/api/software` -> `software`,
    `/mde/api/investigations` -> `investigation`. A route whose segment names
    no entity keeps its own recorded list and nothing is assumed for it.
    """
    segment = route.rstrip("/").rsplit("/", 1)[-1].lower()
    for candidate in (segment, segment.rstrip("s"), segment + "s"):
        if candidate in entities and isinstance(entities[candidate], list):
            return candidate
    return ""


@functools.cache
def properties_by_route() -> dict[str, frozenset[str]]:
    """Every route either reference speaks for, and what its resource carries."""
    return {**_graph_properties(), **_mde_properties()}
