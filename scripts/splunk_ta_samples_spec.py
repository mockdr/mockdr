"""Reduce recorded Splunk add-on events into sourcetype → key-path maps.

The vendors' Splunk add-ons index one API object per event. Splunk's
``attack_data`` repository (Apache-2.0) holds events recorded from the
Splunk Add-on for Microsoft Security; this reduces them to key paths — and
to the JSON *type* each path was seen holding — so the EDR bridge can be
checked against what the add-on really indexes, and a fixture default can be
typed from a real reply rather than guessed:

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


def observed(value: object, prefix: str = "", depth: int = 0) -> set[str]:
    """Every dotted key path a JSON value carries."""
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


def _json_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) or isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


def types(value: object, into: dict[str, set[str]], prefix: str = "",
          depth: int = 0) -> None:
    """Record the JSON type every leaf path was seen holding.

    ``null`` is recorded like any other, because a path that is *only* ever
    null proves nothing about its type — the caller drops those. A path seen
    holding a number is a number, whatever the docs table left unsaid.
    """
    if depth > 8:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            into.setdefault(f"{prefix}{k}", set()).add(_json_type(v))
            types(v, into, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        for item in value[:5]:
            types(item, into, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)


def main() -> int:
    """Write the reduced reference and report what it holds."""
    reduced = {}
    for sourcetype, (url, note) in SAMPLES.items():
        with urllib.request.urlopen(url, timeout=60) as resp:
            lines = [line for line in resp.read().decode().splitlines() if line.strip()]
        paths: set[str] = set()
        seen: dict[str, set[str]] = {}
        for line in lines:
            record = json.loads(line)
            paths |= observed(record)
            types(record, seen)
        # A path only ever null says nothing about its type; one seen with a
        # single non-null type is that type.
        typed = {
            path: sorted(kinds - {"null"})[0]
            for path, kinds in sorted(seen.items())
            if len(kinds - {"null"}) == 1
        }
        # A path seen null even once is nullable, and a nullable field's
        # default is null: `0` for a missing process id would claim PID 0.
        nullable = sorted(path for path, kinds in seen.items() if "null" in kinds)
        reduced[sourcetype] = {
            "source": url,
            "events": len(lines),
            "note": note,
            "paths": sorted(paths),
            "types": typed,
            "nullable": nullable,
        }
        print(f"{sourcetype}: {len(lines)} events, {len(paths)} key paths, "
              f"{len(typed)} typed")
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(f"→ {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
