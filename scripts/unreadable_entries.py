"""Every entry a listing names, read back one at a time.

splunkd's collections are addressable both ways: `/services/authorization/roles`
lists the roles, `/services/authorization/roles/admin` reads one. A client
that lists and then reads — which is what splunklib's `.list()` followed by
`[name]` does — needs both. mockdr listed roles it had no route to read, so
the second call answered 404 for a role the first had just named.

This walks every Splunk collection mockdr serves, takes the entries it names,
and asks for each one back. It reports the entries a listing names and the
mock cannot serve, and it says how many listings it could not check because
they came back empty — a listing with nothing in it proves nothing.

    python scripts/unreadable_entries.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

MOCK = os.environ.get("MOCKDR", "http://localhost:5001/splunk")
AUTH = "Basic " + base64.b64encode(
    f"admin:{os.environ.get('MOCKDR_PASSWORD', 'mockdr-admin')}".encode(),
).decode()


def _get(path: str) -> tuple[int, dict]:
    url = f"{MOCK}/services/{path}"
    url += ("&" if "?" in url else "?") + "output_mode=json"
    req = urllib.request.Request(url, headers={"Authorization": AUTH})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except (urllib.error.URLError, ValueError):
        return 0, {}


def main(collections: list[str]) -> int:
    """Read back every entry each listing names, and report what will not serve."""
    unreadable: list[str] = []
    empty: list[str] = []
    read = 0
    for name in collections:
        status, body = _get(name)
        if status != 200:
            empty.append(f"{name} (listing answered {status})")
            continue
        entries = [str(e.get("name", "")) for e in body.get("entry") or []]
        if not entries:
            empty.append(f"{name} (listed nothing)")
            continue
        for entry in entries:
            code, _ = _get(f"{name}/{urllib.parse.quote(entry, safe='')}")
            read += 1
            if code != 200:
                unreadable.append(f"{name}/{entry} -> {code}")

    print(f"=== UNREADABLE ENTRIES === {read} entry read(s) across "
          f"{len(collections) - len(empty)} listing(s)")
    for line in unreadable:
        print(f"  {line}")
    print(f"\n  {len(unreadable)} entry/entries a listing names and the mock will not serve")
    if empty:
        print(f"  {len(empty)} listing(s) not checked, so their entries were not read at all:")
        for line in empty:
            print(f"    {line}")
    return 1 if unreadable else 0


#: The KV Store's configuration is served only under `nobody`, so the bare
#: path is a refusal rather than a listing — asking there skipped the one
#: collection this audit exists to check.
_KVSTORE = "servicesNS/nobody/search/storage/collections/config"

#: The Splunk collections this repo serves as a listing.
COLLECTIONS = [
    "authorization/roles", "authorization/capabilities", "authentication/users",
    "apps/local", "data/indexes", "saved/searches", "saved/eventtypes",
    "data/inputs/monitor", "data/props/extractions", "data/lookup-table-files",
    "data/transforms/lookups", "admin/macros",
    "messages", "search/jobs", "server/settings",
]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or COLLECTIONS))
