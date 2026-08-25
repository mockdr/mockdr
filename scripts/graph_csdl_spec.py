# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, T201
"""Reduce a Microsoft Graph CSDL into a type → property map.

``graph_v1.0_types.json`` holds what the v1.0 metadata declares, and that is
what most of the mock's Graph surface is measured against. It does not hold
everything the mock serves: Microsoft retires a type by removing it from
v1.0, and ``tiIndicator`` — still reachable, still used by SOAR playbooks
written against it — is gone from v1.0 and lives only in beta. Without a
reference for it the mock invented two properties (``indicatorValue``,
``indicatorType``) that Graph has never had.

So the same reduction runs over both metadata documents. Each entity and
complex type becomes ``{"properties": {name: edm-type}, "base": …,
"open": …}``; enum types become their member names. Nothing else is kept —
no descriptions, no annotations, no examples.

Beta is 6 370 types and the mock serves a handful of them, so a root set may
be named: the closure over those roots' property types is written and the
rest dropped. Widening the mock's beta surface means widening the roots.

    scripts/graph_csdl_spec.py beta  clean_beta_metadata/cleanMetadata.xml \
        tiIndicator
    scripts/graph_csdl_spec.py v1.0  clean_v10_metadata/cleanMetadata.xml

    curl -sSLO https://raw.githubusercontent.com/microsoftgraph/\\
msgraph-metadata/master/clean_beta_metadata/cleanMetadata.xml
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / "data" / "vendor-specs"

_TYPE = re.compile(
    r'<(EntityType|ComplexType) Name="([^"]+)"([^>]*)>(.*?)</\1>', re.S)
_ENUM = re.compile(r'<EnumType Name="([^"]+)"[^>]*>(.*?)</EnumType>', re.S)
_PROPERTY = re.compile(r'<(?:Property|NavigationProperty) Name="([^"]+)" Type="([^"]+)"')
_MEMBER = re.compile(r'<Member Name="([^"]+)"')
_BASE = re.compile(r'BaseType="([^"]+)"')


def reduce_csdl(text: str) -> dict:
    out: dict[str, object] = {}
    for kind, name, attrs, body in _TYPE.findall(text):
        base = _BASE.search(attrs)
        entry: dict[str, object] = {
            "kind": kind, "properties": dict(_PROPERTY.findall(body)),
        }
        if base:
            entry["base"] = base.group(1)
        if 'OpenType="true"' in attrs:
            entry["open"] = True
        out[f"microsoft.graph.{name}"] = entry
    for name, body in _ENUM.findall(text):
        out[f"microsoft.graph.{name}"] = {
            "kind": "EnumType", "members": _MEMBER.findall(body),
        }
    return out


def qualify(type_name: str) -> str:
    """``graph.tiAction`` and ``tiAction`` alike → ``microsoft.graph.tiAction``.

    The clean metadata spells the namespace as the alias ``graph``; the
    reduction spells it in full, as the rest of ``data/vendor-specs`` does.
    """
    return "microsoft.graph." + type_name.rsplit(".", 1)[-1]


def closure(reduced: dict, roots: list[str]) -> dict:
    """``roots`` and every type reachable from their properties."""
    wanted, queue = set(), [qualify(r) for r in roots]
    while queue:
        name = queue.pop()
        entry = reduced.get(name)
        if name in wanted or not isinstance(entry, dict):
            continue
        wanted.add(name)
        queue.extend(
            qualify(re.sub(r"^Collection\(|\)$", "", t))
            for t in (entry.get("properties") or {}).values()
        )
        if entry.get("base"):
            queue.append(qualify(str(entry["base"])))
    return {k: v for k, v in reduced.items() if k in wanted}


def main(version: str, source: Path, roots: list[str]) -> int:
    reduced = reduce_csdl(source.read_text(encoding="utf-8", errors="replace"))
    if roots:
        reduced = closure(reduced, roots)
    out = SPECS / f"graph_{version}_csdl_types.json"
    out.write_text(json.dumps(reduced, indent=1, sort_keys=True) + "\n")
    entities = sum(e.get("kind") == "EntityType" for e in reduced.values())
    print(f"{version}: {len(reduced)} types ({entities} entities) → {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], Path(sys.argv[2]), sys.argv[3:]))
