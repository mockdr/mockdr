"""Which fields Splunk's own SentinelOne support add-on reads from the channel events.

The SentinelOne App for Splunk's source is behind a Splunkbase login, so the
``sentinelone:channel:agents`` event was judged by its name only. Splunk's
``SA-SentinelOneDevices`` (``github.com/splunk/SA-SentinelOneDevices``)
reads that sourcetype for Enterprise Security asset data and names, in its
saved search, every field it expects an event to carry — ``uuid``,
``agentVersion``, ``lastActiveDate``, ``networkInterfaces{}.physical`` …
These are the ``GET /web/api/v2.1/agents`` object's fields, so the channel
event is the API object. The repository carries no licence; only the field
names are kept, in

    data/vendor-specs/s1_splunk_channel_fields.json

A reading proves presence only.

    backend/.venv/bin/python scripts/s1_channel_fields_spec.py
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "s1_splunk_channel_fields.json"
SOURCE = (
    "https://raw.githubusercontent.com/splunk/SA-SentinelOneDevices/main/"
    "SA-SentinelOneDevices/default/savedsearches.conf"
)
# Names the search binds itself (evals, rex captures) and SPL functions.
_OWN = {
    "category", "nt_host", "dns", "bunit", "owner", "priority", "is_expected", "mac", "ip",
    "s1_model_name", "s1_sys_name", "now", "strftime", "strptime", "lower", "mvjoin",
    "mvsort", "mvappend", "replace", "case", "match", "true", "if", "dedup", "rex", "eval",
    "search", "sourcetype", "field", "inputlookup", "outputlookup", "table", "fields",
    "sentinelone_devices", "sa_sentinelone_index", "splunk_last_updated", "coalesce",
    "values", "stats", "by", "mvdedup", "mvfilter", "isnotnull", "null", "len", "tostring",
}


def main() -> int:
    with urllib.request.urlopen(SOURCE, timeout=60) as resp:
        text = resp.read().decode()
    block = text.split("sourcetype=\"sentinelone:channel:agents\"", 1)[1]
    block = block.split("| outputlookup", 1)[0]
    names: set[str] = set()
    # 'networkInterfaces{}.physical' → networkInterfaces[*].physical
    for m in re.finditer(r"'([A-Za-z][A-Za-z0-9_]*)\{\}\.([A-Za-z][A-Za-z0-9_]*)'", block):
        names.add(f"{m.group(1)}[*].{m.group(2)}")
        names.add(m.group(1))
    # "label: ".fieldName   and   strptime(fieldName, ...)   and   lower(fieldName)
    for m in re.finditer(r"(?:\"\.\s*|\(\s*)([A-Za-z][A-Za-z0-9_]*)\s*(?=[,)\\\n])", block):
        name = m.group(1)
        if name not in _OWN and not name.startswith("s1_"):
            names.add(name)
    # dedup uuid · rex field=modelName · mvappend(groupName, siteName)
    for m in re.finditer(r"\bdedup\s+([A-Za-z][A-Za-z0-9_]*)|\bfield=([A-Za-z][A-Za-z0-9_]*)", block):
        names.add(m.group(1) or m.group(2))
    for m in re.finditer(r"mvappend\(([^()]*)\)", block):
        for part in m.group(1).split(","):
            part = part.strip()
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", part) and part not in _OWN:
                names.add(part)
    reduced = {
        "sentinelone:channel:agents": {
            "source": SOURCE,
            "api_route": "GET /web/api/v2.1/agents",
            "fields": sorted(names),
        }
    }
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(f"sentinelone:channel:agents: {len(names)} fields → {OUT.relative_to(ROOT)}")
    print(", ".join(sorted(names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
