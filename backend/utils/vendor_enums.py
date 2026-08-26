"""The order each vendor declares its enum members in.

OData sorts an enum-typed field by where its value sits in the declared
list, not alphabetically. Without that, ``$orderby=severity desc`` answers
`Medium` first where Defender and Graph answer `High` — and a triage client
asking for the worst alerts first works on the wrong ones, with a 200 and no
way to tell.

Both tables are read from what is vendored under ``data/vendor-specs/``
rather than written here: Graph's from the CSDL
(``graph_v1.0_csdl_types.json``), Defender's from its docs' properties
tables (``mde_docs_reduced.json``), which spell the members in order.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

_SPECS = Path(__file__).resolve().parents[2] / "data" / "vendor-specs"

#: Which enum type each Graph field carries, for the entities the mock
#: serves. The members themselves come from the metadata.
_GRAPH_FIELDS: dict[str, str] = {
    "severity": "microsoft.graph.security.alertSeverity",
    "status": "microsoft.graph.security.alertStatus",
    "classification": "microsoft.graph.security.alertClassification",
    "determination": "microsoft.graph.security.alertDetermination",
    "serviceSource": "microsoft.graph.security.serviceSource",
    "detectionSource": "microsoft.graph.security.detectionSource",
}


@functools.cache
def graph_enum_order() -> dict[str, tuple[str, ...]]:
    """Graph's alert and incident enums, field name -> declared order."""
    path = _SPECS / "graph_v1.0_csdl_types.json"
    if not path.exists():
        return {}
    types = json.loads(path.read_text())
    out: dict[str, tuple[str, ...]] = {}
    for field, type_name in _GRAPH_FIELDS.items():
        entry = types.get(type_name)
        if isinstance(entry, dict) and entry.get("kind") == "EnumType":
            out[field] = tuple(entry.get("members") or ())
    # An incident's status is its own enum, and shares the field name.
    incident = types.get("microsoft.graph.security.incidentStatus")
    if isinstance(incident, dict):
        out["incidentStatus"] = tuple(incident.get("members") or ())
    return out


@functools.cache
def mde_enum_order(entity: str = "alerts") -> dict[str, tuple[str, ...]]:
    """Defender's enums for one docs entity, field name -> declared order."""
    path = _SPECS / "mde_docs_reduced.json"
    if not path.exists():
        return {}
    enums = (json.loads(path.read_text()).get("enums") or {}).get(entity) or {}
    return {field: tuple(members) for field, members in enums.items()}
