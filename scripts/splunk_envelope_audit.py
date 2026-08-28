"""What a Splunk collection listing carries around its entries.

splunkd's envelope is not uniform, and mockdr's default was a guess: every
listing claimed `{"create": "/services", "_reload": "/services/_reload"}` —
a create target that exists nowhere in splunkd — and every entry carried an
empty `fields` block. Measured on 10.4.2 across every collection this repo
serves: a listing's top-level links are paths *under the collection itself*,
and a listing entry carries no `fields` block at all (only a single-entity
read does, and then it lists the members that entity accepts).

Run it against a real splunkd and mockdr; it reports the collections where
the two disagree about the envelope rather than about the data.

    python scripts/splunk_envelope_audit.py
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

REAL = os.environ.get("SPLUNK_MGMT", "https://localhost:18089")
MOCK = os.environ.get("MOCKDR", "http://localhost:5001/splunk")
REAL_AUTH = ("admin", os.environ.get("SPLUNK_PASSWORD", "Probe-Passw0rd!"))
MOCK_AUTH = ("admin", os.environ.get("MOCKDR_PASSWORD", "mockdr-admin"))

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _get(base: str, path: str, auth: tuple[str, str]) -> dict | None:
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    url = f"{base}/services/{path}?output_mode=json&count=1"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_CTX) as resp:
            return json.loads(resp.read() or b"{}")
    except (urllib.error.URLError, ValueError):
        return None


def _shape(body: dict) -> dict:
    """The envelope around the entries, and nothing about the entries.

    An empty listing says nothing about an entry, so it reports the entry
    half as unknown rather than as an empty one — an audit that counted
    `[]` here would report a difference it never actually looked at.
    """
    entries = body.get("entry") or []
    entry = entries[0] if entries else None
    return {
        "top_links": dict(body.get("links") or {}),
        "entry_links": sorted(entry.get("links") or {}) if entry else None,
        "fields": ("fields" in entry) if entry else None,
    }


def main(collections: list[str]) -> int:
    """Compare each collection envelope and report the ones that differ."""
    findings = 0
    for name in collections:
        real, mock = _get(REAL, name, REAL_AUTH), _get(MOCK, name, MOCK_AUTH)
        if real is None or mock is None:
            print(f"  skipped {name} ({'real' if real is None else 'mock'} did not answer)")
            continue
        want, got = _shape(real), _shape(mock)
        differs = [
            k for k in ("top_links", "entry_links", "fields")
            if want[k] != got[k] and None not in (want[k], got[k])
        ]
        if not differs:
            if got["entry_links"] is None and want["entry_links"] is not None:
                print(f"  {name}: mock listed nothing, so its entry was not compared")
            continue
        findings += 1
        print(f"  {name}")
        for key in ("top_links", "entry_links", "fields"):
            if want[key] != got[key] and None not in (want[key], got[key]):
                print(f"    {key:12s} real {want[key]}\n    {'':12s} mock {got[key]}")
    print(f"\n{findings} collection(s) whose envelope differs")
    return 1 if findings else 0


#: Every collection this repo serves that 10.4.2 also serves as a listing.
COLLECTIONS = [
    "authorization/capabilities", "authorization/roles", "authentication/users",
    "messages", "saved/searches", "data/indexes", "server/settings", "server/info",
    "search/jobs", "apps/local", "data/inputs/monitor", "admin/macros",
    "data/props/extractions", "licenser/licenses", "data/ui/views",
    "storage/collections/config", "data/lookup-table-files", "data/transforms/lookups",
    "saved/eventtypes", "data/props/sourcetype-rename",
]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or COLLECTIONS))
