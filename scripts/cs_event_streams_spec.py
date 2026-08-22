# ruff: noqa: ANN001, ANN201, ANN202, D103, E402
"""Reduce recorded CrowdStrike Event Streams events into a per-type key map.

The Falcon Event Streams API (what the SIEM connector and the Splunk TA
consume) is documented behind the customer portal, but Elastic's
``integrations`` repository ships events recorded from it as pipeline test
data (``packages/crowdstrike/data_stream/falcon/_dev/test/pipeline/*.log``).
The repository is under the Elastic License 2.0, so the files are not
vendored; this reads a local copy and keeps the facts — the ``metadata``
and ``event`` keys each event type carries — in
``data/vendor-specs/cs_event_streams_reduced.json``. A recording proves
presence only.

    # fetch packages/crowdstrike/data_stream/falcon/_dev/test/pipeline/*.log
    backend/.venv/bin/python scripts/cs_event_streams_spec.py /tmp/es-crowdstrike
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "cs_event_streams_reduced.json"


def observed(value, prefix: str = "", depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 6:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}{k}")
            out |= observed(v, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        for item in value[:5]:
            out |= observed(item, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)
    return out


def main(samples: Path) -> int:
    by_type: dict[str, dict] = {}
    for f in sorted(glob.glob(str(samples / "*.log"))):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = (event.get("metadata") or {}).get("eventType")
            if not kind:
                continue
            entry = by_type.setdefault(kind, {"samples": 0, "paths": set(), "sources": set()})
            entry["samples"] += 1
            entry["paths"] |= observed(event)
            entry["sources"].add(Path(f).name)
    reduced = {
        "_provenance": (
            "elastic/integrations packages/crowdstrike/data_stream/falcon/_dev/test/pipeline"
            " (Elastic License 2.0; key paths only)"
        ),
        **{
            k: {
                "samples": v["samples"],
                "sources": sorted(v["sources"]),
                "paths": sorted(v["paths"]),
            }
            for k, v in sorted(by_type.items())
        },
    }
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    for k, v in sorted(by_type.items()):
        print(f"  {k:40} {v['samples']:3} samples  {len(v['paths']):3} paths")
    print(f"→ {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: cs_event_streams_spec.py <dir with the recorded *.log files>")
    raise SystemExit(main(Path(sys.argv[1])))
