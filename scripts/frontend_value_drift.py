#!/usr/bin/env python3
"""Ask whether the values the console compares against ever actually occur.

The three drift scripts beside this one ask about names: does the route
exist, does the answer carry the field, does the route read the parameter.
This asks about values. `status === 'Resolved'` against an API that says
`resolved` is a branch that never runs -- a badge that never colours, a
filter that matches nothing, a button that never appears -- and nothing can
see it: the field is real, the comparison is well typed, the page renders.

So: harvest every value each vendor actually answers with, per property, and
compare them with the string literals the console tests that property
against.

Only enum-like properties are compared -- at most 20 distinct values across
at least 5 records. A property whose values are identifiers has no
vocabulary to be wrong about, and comparing against one would report every
`id === 'alerts'` written for a tab.
"""
from __future__ import annotations

import json
import logging
import re
import sys
import warnings
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend" / "src"

sys.path.insert(0, str(ROOT / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=False).__enter__()

#: Which mount each console folder talks to. Views at the top level are the
#: SentinelOne console; `elastic/` speaks to both Elasticsearch and Kibana.
FOLDER_MOUNTS = {
    "mde": ("/mde",), "cs": ("/cs",), "graph": ("/graph",),
    "sentinel": ("/sentinel",), "splunk": ("/splunk",), "xdr": ("/xdr/public_api/v1",),
    "elastic": ("/elastic", "/kibana"),
}
DEFAULT_MOUNT = ("/web/api/v2.1",)

STATIC_AUTH = {
    "/web/api/v2.1": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
    "/xdr/public_api/v1": {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
    "/splunk": {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"},
    "/elastic": {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="},
    "/kibana": {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="},
}
OAUTH = {
    "/cs": ("/cs/oauth2/token", {"client_id": "cs-mock-admin-client",
                                 "client_secret": "cs-mock-admin-secret"}),
    "/mde": ("/mde/oauth2/v2.0/token", {
        "grant_type": "client_credentials", "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "scope": "https://api.securitycenter.microsoft.com/.default"}),
    "/graph": ("/graph/oauth2/v2.0/token", {
        "grant_type": "client_credentials", "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "scope": "https://graph.microsoft.com/.default"}),
    "/sentinel": ("/sentinel/oauth2/v2.0/token", {
        "grant_type": "client_credentials", "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "scope": "https://management.azure.com/.default"}),
}

#: `record.status === 'open'`, and the `!==` that reads the same way.
_COMPARISON = re.compile(r"[\w\]\)]\.(?P<prop>[A-Za-z_]\w*)\s*[!=]==\s*'(?P<value>[^']{1,60})'")
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)

#: Comparisons that are right as they stand, each with the reason. A new
#: entry belongs here only with one.
KNOWN: dict[tuple[str, str, str], str] = {
    ("components/shared/Toasts.vue", "kind", "error"):
        "a toast's own kind, local to the console; the name collides with a "
        "field SentinelOne answers with and nothing reads it from there",
    ("views/graph/GraphDashboardView.vue", "status", "redirected"):
        "`microsoft.graph.security.incidentStatus` declares it and means "
        "'merged into another incident'. This mock models no merge, so it "
        "never answers with it -- and the console is right to handle a state "
        "the real product has. Seeding it would be a claim about a "
        "relationship nothing here has.",
}

#: An enum has few values and many records; an identifier has neither.
_MAX_DISTINCT = 20
_MIN_RECORDS = 5


def headers(mount: str) -> dict[str, str]:
    """The header this mount wants, minted where it is an OAuth one."""
    if mount in STATIC_AUTH:
        return dict(STATIC_AUTH[mount])
    path, form = OAUTH[mount]
    token = client.post(path, data=form).json().get("access_token", "")
    return {"Authorization": f"Bearer {token}"}


def harvest(value: object, seen: dict[str, set[str]], counts: dict[str, int]) -> None:
    """Record every string a property is answered with, however deep it sits."""
    if isinstance(value, dict):
        for key, inner in value.items():
            if isinstance(inner, str):
                seen[key].add(inner)
                counts[key] += 1
            else:
                harvest(inner, seen, counts)
    elif isinstance(value, list):
        for item in value:
            harvest(item, seen, counts)


def vocabulary(mounts: tuple[str, ...]) -> tuple[dict[str, set[str]], dict[str, int]]:
    """Every value each property is answered with, across a mount's GETs."""
    seen: dict[str, set[str]] = defaultdict(set)
    counts: dict[str, int] = defaultdict(int)
    paths = app.openapi()["paths"]
    for mount in mounts:
        head = headers(mount)
        for path, operations in paths.items():
            if not path.startswith(mount) or "get" not in operations or "{" in path:
                continue
            response = client.get(path, headers=head)
            if response.status_code != 200:
                continue
            try:
                harvest(response.json(), seen, counts)
            except json.JSONDecodeError:
                continue
    return seen, counts


def mounts_for(path: Path) -> tuple[str, ...]:
    """Which mount a console file talks to, by where it sits."""
    for part in path.parts:
        if part in FOLDER_MOUNTS:
            return FOLDER_MOUNTS[part]
    return DEFAULT_MOUNT


def main() -> int:
    """Compare the console's literals with the values each vendor answers."""
    sources = [p for folder in ("views", "stores", "components")
               for p in (FRONTEND / folder).rglob("*")
               if p.suffix in {".vue", ".ts"} and "__tests__" not in p.parts]

    by_mount: dict[tuple[str, ...], list[tuple[Path, str, str]]] = defaultdict(list)
    for source in sorted(sources):
        text = _COMMENT.sub(" ", source.read_text())
        for match in _COMPARISON.finditer(text):
            by_mount[mounts_for(source)].append(
                (source, match.group("prop"), match.group("value")))

    findings: list[str] = []
    compared = skipped = known = 0

    for mounts, comparisons in sorted(by_mount.items()):
        seen, counts = vocabulary(mounts)
        for source, prop, value in comparisons:
            values = seen.get(prop)
            if (values is None or len(values) > _MAX_DISTINCT
                    or counts[prop] < _MIN_RECORDS):
                skipped += 1
                continue
            where = source.relative_to(FRONTEND)
            if (str(where), prop, value) in KNOWN:
                known += 1
                continue
            compared += 1
            if value not in values:
                findings.append(
                    f"{where}: {prop} === '{value}' — answered with "
                    f"{', '.join(sorted(values))[:80]}")

    print(f"=== FRONTEND VALUE DRIFT === {compared} comparison(s) against a vocabulary "
          f"the mock answers with")
    print()
    for line in sorted(set(findings)):
        print(f"  {line}")
    print(f"  {len(findings)} comparison(s) against a value that never occurs")
    print(f"  {skipped} skipped: the property is not answered here, or its values "
          f"are identifiers rather than a vocabulary")
    print(f"  {known} known and right as they stand, each named in the script "
          f"with the reason")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
