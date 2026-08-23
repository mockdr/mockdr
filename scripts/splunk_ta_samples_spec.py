"""Reduce recorded Splunk add-on events into sourcetype → key-path maps.

The vendors' Splunk add-ons index one API object per event. Splunk's
``attack_data`` repository (Apache-2.0) holds events recorded from the
Splunk Add-on for Microsoft Security; this reduces them to key paths so the
EDR bridge can be checked against what the add-on really indexes:

    data/vendor-specs/splunk_ta_samples_reduced.json

    backend/.venv/bin/python scripts/splunk_ta_samples_spec.py
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "splunk_ta_samples_reduced.json"

#: sourcetype → (source url, note)
SAMPLES = {
    "ms:defender:atp:alerts": (
        (
            "https://media.githubusercontent.com/media/splunk/attack_data/master/"
            "datasets/suspicious_behaviour/alerts/defender_atp_alerts.log"
        ),
        (
            "Splunk Add-on for Microsoft Security, Defender for Endpoint /api/alerts "
            "with evidence expanded; recorded 2021 (domains, loggedOnUsers and "
            "evidence.registryValueName have since left the documented alert)."
        ),
    ),
}


def observed(value, prefix: str = "", depth: int = 0) -> set[str]:
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
    reduced = {}
    for sourcetype, (url, note) in SAMPLES.items():
        with urllib.request.urlopen(url, timeout=60) as resp:
            lines = [line for line in resp.read().decode().splitlines() if line.strip()]
        paths: set[str] = set()
        for line in lines:
            paths |= observed(json.loads(line))
        reduced[sourcetype] = {
            "source": url,
            "events": len(lines),
            "note": note,
            "paths": sorted(paths),
        }
        print(f"{sourcetype}: {len(lines)} events, {len(paths)} key paths")
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(f"→ {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
