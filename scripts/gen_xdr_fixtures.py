# ruff: noqa: ANN001, ANN201, ANN202, D103, E402
"""Generate default reply shapes for Cortex XDR routes from recorded responses.

Palo Alto publishes no machine-readable spec; the XSOAR content pack's
``test_data`` holds responses recorded from the real product
(``data/vendor-specs/xsoar-samples/CortexXDR``, mapped to routes by
``scripts/xsoar_samples_spec.py``). For each route this writes the sample's
``reply`` as a type-correct default object — "" / 0 / false / [] with one
template item per list — to ``backend/infrastructure/fixtures/xdr/<slug>.json``;
the handlers deep-merge their data over it.

    backend/.venv/bin/python scripts/gen_xdr_fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from xsoar_samples_spec import CORE, SAMPLES, XDR, split_route, unwrap, wrap  # noqa: E402

OUT = ROOT / "backend" / "infrastructure" / "fixtures" / "xdr"


def defaults(value):
    if isinstance(value, dict):
        return {k: defaults(v) for k, v in value.items()}
    if isinstance(value, list):
        merged: dict = {}
        for item in value:
            if isinstance(item, dict):
                for k, v in defaults(item).items():
                    merged.setdefault(k, v)
        return [merged] if merged else []
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0
    return "" if value is None or isinstance(value, str) else value


def _insert(tree: dict, path: str) -> None:
    """Create the nested default for a dotted path; ``x[*]`` is a list with one template item."""
    node = tree
    tokens = path.split(".")
    for i, token in enumerate(tokens):
        is_list = token.endswith("[*]")
        name = token[:-3] if is_list else token
        last = i == len(tokens) - 1
        if is_list:
            if not isinstance(node.get(name), list) or not node[name]:
                node[name] = [{}]
            if last:
                return
            node = node[name][0]
        elif last:
            node.setdefault(name, "")
        else:
            if not isinstance(node.get(name), dict):
                node[name] = {}
            node = node[name]


def slug(route: str) -> str:
    return route.split(" ", 1)[1].strip("/").removeprefix("public_api/v1/").replace("/", "_")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    by_route: dict[str, dict] = {}
    for pack, name, route in [("CortexXDR", n, r) for n, r in XDR.items()] + [
        ("CoreIRApiModule", n, r) for n, r in CORE.items()
    ]:
        route, wrap_at = split_route(route)
        path = SAMPLES / pack / name
        if not path.exists():
            continue
        sample = wrap(unwrap(json.load(open(path))), wrap_at)
        reply = sample.get("reply", sample) if isinstance(sample, dict) else sample
        shape = defaults(reply)
        if isinstance(shape, dict):
            existing = by_route.get(route)
            by_route[route] = {**(existing if isinstance(existing, dict) else {}), **shape}
        elif isinstance(shape, list):
            # a bare list in reply: the fixture is the merged template item
            existing = by_route.get(route)
            template = {
                **(existing[0] if isinstance(existing, list) and existing else {}),
                **(shape[0] if shape else {}),
            }
            by_route[route] = [template] if template else []
    # The transcribed reference adds routes no recording covers, and fields a
    # recording happened to omit: both become defaults too.
    for extra in ("xdr_openapi_reduced.json", "xdr_connector_reduced.json"):
        transcribed = ROOT / "data" / "vendor-specs" / extra
        if not transcribed.exists():
            continue
        for route, entry in json.load(open(transcribed)).items():
            if not isinstance(entry, dict) or " " not in route:
                continue
            key = route.rstrip("/")
            target = next((r for r in by_route if r.rstrip("/") == key), route)
            declared_list = any(p.startswith("reply[*]") for p in entry.get("paths", []))
            shape = by_route.setdefault(target, [] if declared_list else {})
            for path in entry.get("paths", []):
                if path.startswith("reply.") and isinstance(shape, dict):
                    _insert(shape, path[len("reply.") :])
                elif path.startswith("reply[*].") and isinstance(shape, list):
                    if not shape:
                        shape.append({})
                    _insert(shape[0], path[len("reply[*].") :])
    for route, shape in sorted(by_route.items()):
        (OUT / f"{slug(route)}.json").write_text(
            json.dumps({"route": route, "reply": shape}, indent=1) + "\n"
        )
        print(f"  {slug(route):40} {len(shape):3} top-level keys")
    print(f"{len(by_route)} fixtures → {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
