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
from xsoar_samples_spec import SAMPLES, XDR, unwrap  # noqa: E402

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


def slug(route: str) -> str:
    return route.split(" ", 1)[1].strip("/").removeprefix("public_api/v1/").replace("/", "_")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    by_route: dict[str, dict] = {}
    for name, route in XDR.items():
        path = SAMPLES / "CortexXDR" / name
        if not path.exists():
            continue
        sample = unwrap(json.load(open(path)))
        reply = sample.get("reply", sample) if isinstance(sample, dict) else sample
        shape = defaults(reply)
        if isinstance(shape, dict):
            by_route[route] = {**by_route.get(route, {}), **shape}
    for route, shape in sorted(by_route.items()):
        (OUT / f"{slug(route)}.json").write_text(
            json.dumps({"route": route, "reply": shape}, indent=1) + "\n"
        )
        print(f"  {slug(route):40} {len(shape):3} top-level keys")
    print(f"{len(by_route)} fixtures → {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
