"""Reduce Elastic's transcription of Cortex XDR ``get_alerts_multi_events`` replies.

Palo Alto's reference for the Cortex XDR API is rendered client-side and
publishes no recordings; the Splunk Add-on for Palo Alto Networks reads
alerts with ``alerts/get_alerts_multi_events`` and the shape stayed
unjudged. Elastic's ``integrations`` repository ingests the same API and
carries, for its own tests, a transcription of the replies with placeholder
values (``packages/panw_cortex_xdr/data_stream/alerts/_dev/deploy/docker/
http-mock-config.yml``): the v1 form — an alert with its ``events`` list —
and the flattened v2 form. The repository is under the Elastic License 2.0,
so nothing of it is vendored; this downloads the file and keeps only the
facts — the key paths a reply carries — in

    data/vendor-specs/xdr_alerts_multi_events_reduced.json

A transcription proves presence only.

    backend/.venv/bin/python scripts/cortex_alerts_spec.py
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "xdr_alerts_multi_events_reduced.json"
SOURCE = (
    "https://raw.githubusercontent.com/elastic/integrations/main/"
    "packages/panw_cortex_xdr/data_stream/alerts/_dev/deploy/docker/http-mock-config.yml"
)
_RULE = re.compile(r"- path: (\S+).*?minify_json `\s*(\{.*?\})\s*`", re.DOTALL)


def observed(value: object, prefix: str = "", depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 8:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}{k}")
            out |= observed(v, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        for item in value[:5]:
            out |= observed(item, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)
    return out


def main() -> int:
    with urllib.request.urlopen(SOURCE, timeout=60) as resp:
        text = resp.read().decode()
    reduced: dict[str, dict] = {}
    for path, body in _RULE.findall(text):
        route = f"POST {path}/"
        entry = reduced.setdefault(route, {"source": SOURCE, "replies": 0, "paths": set()})
        entry["replies"] += 1
        entry["paths"] |= observed(json.loads(body))
    for route, entry in reduced.items():
        entry["paths"] = sorted(entry["paths"])
        print(f"{route}: {entry['replies']} transcribed replies, {len(entry['paths'])} key paths")
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(f"→ {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
