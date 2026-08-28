"""Which query arguments splunkd's handlers take, and whether mockdr agrees.

splunkd refuses an argument its handler does not take — `Argument "zzz" is
not supported by this handler.`, naming the alphabetically first of them —
and mockdr answered 200 and ignored it. A client that misspelled `sort_key`
got the collection in whatever order the mock held it and read that as the
order it had asked for.

Imitating the refusal needs the accepted set for every route, and getting it
wrong the other way invents a 400 splunkd never answers. So this asks
splunkd itself, one argument at a time, and checks mockdr in both
directions: every argument splunkd takes, mockdr must not refuse; an
argument neither knows, mockdr must refuse.

The oracle is the message, not the status: splunkd calls an unsupported
argument unsupported, and answers 400 for a *bad value* of a supported one —
`?output_mode=1` is the second and `?zzz=1` the first.

    python scripts/splunk_arg_audit.py

Needs a real splunkd (`SPLUNK_MGMT`, default https://localhost:18089) and
mockdr (`MOCKDR`, default http://localhost:5001/splunk).
"""

from __future__ import annotations

import base64
import os
import ssl
import sys
import urllib.error
import urllib.request

REAL = os.environ.get("SPLUNK_MGMT", "https://localhost:18089")
MOCK = os.environ.get("MOCKDR", "http://localhost:5001/splunk")
REAL_AUTH = "Basic " + base64.b64encode(
    f"admin:{os.environ.get('SPLUNK_PASSWORD', 'Probe-Passw0rd!')}".encode()).decode()
MOCK_AUTH = "Basic " + base64.b64encode(
    f"admin:{os.environ.get('MOCKDR_PASSWORD', 'mockdr-admin')}".encode()).decode()

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

#: Everything any of these handlers might take. Membership is decided by
#: measurement; this only has to be a superset worth asking about.
CANDIDATES = (
    "count", "offset", "search", "sort_dir", "sort_key", "sort_mode", "f",
    "output_mode", "output_mode_v2", "summarize", "add_orphan_field", "datatype",
    "prefix", "max_matches", "earliest_time", "latest_time", "time", "now",
    "refresh", "app", "owner", "sharing", "explain", "index", "segmentation",
)

#: The GET routes this compares.
ROUTES = (
    "/services/admin/macros", "/services/apps/local",
    "/services/authentication/current-context", "/services/authentication/users",
    "/services/authorization/capabilities",
    "/services/authorization/capabilities/capabilities",
    "/services/authorization/grantable_capabilities", "/services/authorization/roles",
    "/services/data/indexes", "/services/data/inputs/monitor",
    "/services/data/inputs/tcp/raw", "/services/data/lookup-table-files",
    "/services/data/props/extractions", "/services/data/transforms/lookups",
    "/services/kvstore/status", "/services/licenser/licenses", "/services/messages",
    "/services/saved/eventtypes", "/services/saved/searches",
    "/services/server/health/splunkd", "/services/server/info",
    "/services/server/settings", "/services/server/settings/settings",
    "/services/server/status", "/services/data/indexes-extended",
    "/services/alerts/fired_alerts",
)

_UNSUPPORTED = b"is not supported by this handler"


def _ask(base: str, auth: str, path: str, key: str) -> tuple[int, bytes]:
    req = urllib.request.Request(f"{base}{path}?{key}=1", headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_CTX) as resp:
            return resp.status, resp.read()[:300]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()[:300]
    except Exception as exc:  # noqa: BLE001 - a release tool, not a request path
        return 0, str(exc)[:80].encode()


def main() -> int:
    """Compare every route's accepted arguments, in both directions."""
    invented: list[str] = []
    ignored: list[str] = []
    unchecked: list[str] = []
    asked = 0
    for route in ROUTES:
        code, body = _ask(REAL, REAL_AUTH, route, "zzzqqq")
        asked += 1
        if not (code == 400 and _UNSUPPORTED in body):
            unchecked.append(f"{route} (splunkd did not refuse an unknown one)")
            continue
        for key in (*CANDIDATES, "zzzqqq"):
            code, body = _ask(REAL, REAL_AUTH, route, key)
            asked += 1
            theirs = code == 400 and _UNSUPPORTED in body
            code, body = _ask(MOCK, MOCK_AUTH, route, key)
            ours = code == 400 and _UNSUPPORTED in body
            if ours and not theirs:
                invented.append(f"{route}?{key}")
            elif theirs and not ours:
                ignored.append(f"{route}?{key}")

    print(f"=== SPLUNK ARGUMENTS === {asked} question(s) across {len(ROUTES)} route(s)")
    for line in invented:
        print(f"  refused though splunkd takes it: {line}")
    for line in ignored:
        print(f"  ignored though splunkd refuses it: {line}")
    print(f"\n  {len(invented)} invented refusal(s), "
          f"{len(ignored)} argument(s) ignored that splunkd refuses")
    if unchecked:
        print(f"  {len(unchecked)} route(s) not compared:")
        for line in unchecked:
            print(f"    {line}")
    return 1 if invented or ignored else 0


if __name__ == "__main__":
    sys.exit(main())
