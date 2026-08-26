# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, T201
r"""Reduce a Microsoft Graph CSDL into a type → property map.

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

_SCHEMA = re.compile(r'<Schema Namespace="([^"]+)"[^>]*>(.*?)</Schema>', re.S)
#: A type is written either paired or self-closing. Matching only the paired
#: form let a self-closing one swallow everything up to the next closing tag,
#: and 184 of the security namespace's types came back instead of 700.
_TYPE = re.compile(
    r'<(EntityType|ComplexType) Name="([^"]+)"((?:[^>"]|"[^"]*")*?)'
    r'(?:/>|>(.*?)</\1>)', re.S)
_ENUM = re.compile(
    r'<EnumType Name="([^"]+)"((?:[^>"]|"[^"]*")*?)(?:/>|>(.*?)</EnumType>)', re.S)
_PROPERTY = re.compile(r'<(?:Property|NavigationProperty) Name="([^"]+)" Type="([^"]+)"')
_MEMBER = re.compile(r'<Member Name="([^"]+)"')
_BASE = re.compile(r'BaseType="([^"]+)"')


def reduce_csdl(text: str) -> dict:
    """Every type in the document, qualified by the schema that declares it.

    The namespace matters: Graph puts its security types in
    ``microsoft.graph.security`` and refers to them from inside that schema
    as ``self.deviceEvidence``. Reading every ``self.`` as
    ``microsoft.graph.`` put `deviceEvidence`'s enums in a namespace that
    does not exist, and the closure lost them.
    """
    out: dict[str, object] = {}
    schemas = _SCHEMA.findall(text) or [("microsoft.graph", text)]
    for namespace, block in schemas:
        for kind, name, attrs, body in _TYPE.findall(block):
            body = body or ""
            base = _BASE.search(attrs)
            entry: dict[str, object] = {
                "kind": kind, "namespace": namespace,
                "properties": dict(_PROPERTY.findall(body)),
            }
            if base:
                entry["base"] = qualify(base.group(1), namespace)
            if 'OpenType="true"' in attrs:
                entry["open"] = True
            out[f"{namespace}.{name}"] = entry
        for name, _attrs, body in _ENUM.findall(block):
            out[f"{namespace}.{name}"] = {
                "kind": "EnumType", "namespace": namespace,
                "members": _MEMBER.findall(body or ""),
            }
    return out


def qualify(type_name: str, namespace: str = "microsoft.graph") -> str:
    """Spell a type reference in full, from where it was written.

    The clean metadata spells the main namespace as the alias ``graph`` and
    a schema's own namespace as ``self``; anything else is already written
    out. ``namespace`` is the schema the reference appears in, which is what
    ``self`` means.
    """
    head, _, name = type_name.rpartition(".")
    if head in ("", "self"):
        return f"{namespace}.{name}"
    if head == "graph":
        return f"microsoft.graph.{name}"
    return type_name


def closure(reduced: dict, roots: list[str]) -> dict:
    """``roots`` and every type reachable from their properties."""
    # A root may be given short (`tiIndicator`) or in full
    # (`microsoft.graph.security.deviceEvidence`).
    wanted, queue = set(), [r if "." in r else qualify(r) for r in roots]
    while queue:
        name = queue.pop()
        entry = reduced.get(name)
        if name in wanted or not isinstance(entry, dict):
            continue
        wanted.add(name)
        namespace = str(entry.get("namespace") or "microsoft.graph")
        queue.extend(
            qualify(re.sub(r"^Collection\(|\)$", "", t), namespace)
            for t in (entry.get("properties") or {}).values()
        )
        if entry.get("base"):
            queue.append(str(entry["base"]))
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
