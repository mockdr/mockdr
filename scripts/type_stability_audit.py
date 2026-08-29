# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Ask whether a field means the same thing everywhere it appears.

A client writes one parser per field: `created_at` is a date, `severity` is a
string, `count` is a number. It writes that parser once and runs it over
every record the API hands it. So a field that is a string in one record and
a number in the next breaks it — and which of the two is *right* barely
matters, because a product does not answer both.

This sweeps every listing route, walks every record to its leaves, and
collects what each field path actually held:

* **type** — a field that is sometimes a string and sometimes a number, or
  sometimes an object and sometimes a list. `null` is not a change of type:
  every product here uses it for "not set".
* **date format** — a field whose values are dates in more than one
  notation: ISO with a `Z`, ISO with an offset, an offset without a colon,
  epoch seconds, epoch milliseconds. Splunk alone uses three of those in one
  API, but never two for the same field.

Both are judged *within one route*, not across a vendor: `severity` is a
string on a Graph alert and a number on a Graph tiIndicator, and both are
right, because they are different fields of different types that happen to
share a name. A field must mean one thing to the clients of the route that
serves it; whether the same *name* means something else elsewhere is the
vendor's business. The one drift that would escape this — a field typed one
way in a listing and another in a fetch by id — is what
`consistency_audit.py` compares.

Exit status 1 when anything is flagged.

    backend/.venv/bin/python scripts/type_stability_audit.py [mount ...]
"""

import base64
import logging
import re
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False).__enter__()


def oauth(path, cid, sec, extra=None):
    response = client.post(path, data={
        "grant_type": "client_credentials", "client_id": cid,
        "client_secret": sec, **(extra or {}),
    })
    if response.status_code not in (200, 201):
        return None
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(
        f"{user}:{password}".encode()).decode()}


AUTH = {
    "web": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
    "cs": oauth("/cs/oauth2/token", "cs-mock-admin-client", "cs-mock-admin-secret"),
    "mde": oauth("/mde/oauth2/v2.0/token", "mde-mock-admin-client", "mde-mock-admin-secret",
                 {"scope": "https://api.securitycenter.microsoft.com/.default"}),
    "graph": oauth("/graph/oauth2/v2.0/token", "graph-mock-admin-client",
                   "graph-mock-admin-secret", {"scope": "https://graph.microsoft.com/.default"}),
    "sentinel": oauth("/sentinel/oauth2/v2.0/token", "sentinel-mock-client-id",
                      "sentinel-mock-client-secret",
                      {"scope": "https://management.azure.com/.default"}),
    "xdr": {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
    "splunk": _basic("admin", "mockdr-admin"),
    "elastic": _basic("elastic", "mock-elastic-password"),
    "kibana": {**_basic("elastic", "mock-elastic-password"), "kbn-xsrf": "true"},
}

#: How a date can be written. A field must not use two of these.
_NOTATIONS = (
    ("iso-z", re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")),
    ("iso-offset", re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}$")),
    ("iso-offset-no-colon",
     re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{4}$")),
    ("iso-naive", re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$")),
    ("date-only", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
)

#: A field whose *name* says it is a time. Only these are checked for
#: notation, so an id that happens to look like a number is left alone. The
#: name is split on camelCase first, or `createdAt` and `expirationDateTime`
#: — two of the commonest date fields here — would not match at all.
_TIMEISH = re.compile(
    r"(^|_)(time|date|timestamp|at|seen|checkin|expiration|expiry|updated|created"
    r"|modified|joined|login|start|end|since|until)(_?(utc|ms|epoch))?$",
    re.IGNORECASE,
)


def timeish(field: str) -> bool:
    """Whether a field's name says it holds a time."""
    name = field.replace("[]", "").rsplit(".", 1)[-1]
    return bool(_TIMEISH.search(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)))


def notation(value):
    """Which notation a value is written in, or None if it is not a date."""
    if isinstance(value, str):
        for name, pattern in _NOTATIONS:
            if pattern.match(value):
                return name
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # Epoch seconds and epoch milliseconds are both plausible integers; the
    # boundary is where a seconds value would be far in the future.
    if 10**8 < value < 10**11:
        return "epoch-seconds"
    if 10**11 <= value < 10**14:
        return "epoch-millis"
    return None


def kind(value):
    """The JSON type of a value, with null folded away."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def leaves(record, prefix=""):
    """Every leaf of a record, as ``(path, value)``."""
    if isinstance(record, dict):
        for key, value in record.items():
            yield from leaves(value, f"{prefix}.{key}" if prefix else key)
    elif isinstance(record, list):
        for value in record:
            yield from leaves(value, f"{prefix}[]")
    else:
        yield prefix, record


#: How to ask each mount for a whole page. One dictionary for all of them
#: swept nothing from splunkd, which refuses an argument it does not declare
#: — correctly, and silently as far as a tool that ignores the status is
#: concerned.
PAGING = {
    "web": {"limit": 200},
    "cs": {"limit": 200},
    "mde": {"$top": 200},
    "graph": {"$top": 200},
    # Kibana's three families each spell it differently, and its cases route
    # refuses a key it does not know — so this is per route, not per mount.
    "kibana": {},
    # Without `output_mode` splunkd answers Atom XML and the parse fails.
    "splunk": {"count": 0, "output_mode": "json"},
    "xdr": {},
    "elastic": {},
    "sentinel": {"api-version": "2024-03-01"},
}

#: The listings to sweep, and where each keeps its records.
ROUTES = {
    "web": [("/web/api/v2.1/agents", "data"), ("/web/api/v2.1/threats", "data"),
            ("/web/api/v2.1/activities", "data"), ("/web/api/v2.1/users", "data"),
            ("/web/api/v2.1/groups", "data"), ("/web/api/v2.1/sites", "data.sites")],
    "cs": [("/cs/devices/combined/host-groups/v1", "resources"),
           ("/cs/iocs/combined/indicator/v1", "resources"),
           # Falcon caps this one at 100, and says so.
           ("/cs/discover/combined/applications/v1", "resources", {"limit": 100}),
           ],
    "mde": [("/mde/api/machines", "value"), ("/mde/api/alerts", "value"),
            ("/mde/api/indicators", "value"), ("/mde/api/machineactions", "value")],
    "graph": [("/graph/v1.0/security/alerts_v2", "value"),
              ("/graph/v1.0/security/incidents", "value"),
              ("/graph/v1.0/users", "value"),
              ("/graph/v1.0/deviceManagement/managedDevices", "value")],
    "xdr": [],
    "kibana": [("/kibana/api/cases/_find", "cases", {"perPage": 100}),
               ("/kibana/api/detection_engine/rules/_find", "data", {"per_page": 100}),
               ("/kibana/api/exception_lists/_find", "data",
                {"per_page": 100, "namespace_type": "single"}),
               ("/kibana/api/endpoint/metadata", "data", {"pageSize": 100})],
    "splunk": [("/splunk/services/data/indexes", "entry"),
               ("/splunk/services/saved/searches", "entry"),
               ("/splunk/services/authentication/users", "entry")],
}


def dig(body, where):
    """Follow a dotted path to the list of records."""
    if where is None:
        return body if isinstance(body, list) else None
    cursor = body
    for step in where.split("."):
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(step)
    return cursor if isinstance(cursor, list) else None


def records():
    """Every record the sweep can reach, with where it came from."""
    for mount, routes in ROUTES.items():
        headers = AUTH[mount]
        for route in routes:
            path, where = route[0], route[1]
            params = route[2] if len(route) > 2 else PAGING[mount]
            response = client.get(path, headers=headers, params=params)
            if response.status_code != 200:
                print(f"  ! {path} answered {response.status_code}; not swept",
                      file=sys.stderr)
                continue
            try:
                found = dig(response.json(), where)
            except ValueError:
                continue
            for record in found or []:
                yield mount, path, record

    # Falcon's entity routes take the ids its queries routes answer, so the
    # sweep has to walk the pair rather than a single listing.
    headers = AUTH["cs"]
    for query, entities in (
        ("/cs/devices/queries/devices/v1", "/cs/devices/entities/devices/v2"),
        ("/cs/alerts/queries/alerts/v2", None),
    ):
        # Both entity routes are POSTs: Falcon reads the id list from a body.
        listed = client.get(query, headers=headers, params={"limit": 200})
        if listed.status_code != 200:
            print(f"  ! {query} answered {listed.status_code}; not swept", file=sys.stderr)
            continue
        ids = listed.json().get("resources") or []
        if not ids:
            continue
        if entities:
            response = client.post(entities, headers=headers, json={"ids": ids[:100]})
        else:
            response = client.post("/cs/alerts/entities/alerts/v2", headers=headers,
                                   json={"composite_ids": ids[:100]})
        if response.status_code != 200:
            print(f"  ! {entities or 'alerts/v2'} answered {response.status_code};"
                  f" not swept", file=sys.stderr)
            continue
        for record in response.json().get("resources") or []:
            yield "cs", entities or "/cs/alerts/entities/alerts/v2", record

    # Elasticsearch keeps its records in search hits rather than a listing.
    headers = AUTH["elastic"]
    for index in ("logs-endpoint", "metrics-endpoint", ".alerts-security",
                  ".siem-signals"):
        response = client.post(f"/elastic/{index}/_search", headers=headers,
                               json={"size": 200})
        if response.status_code != 200:
            continue
        for hit in dig(response.json(), "hits.hits") or []:
            yield "elastic", f"{index}/_search", hit.get("_source") or {}

    # Cortex is POST-only, so its listings need a body.
    headers = AUTH["xdr"]
    for path, where in (
        ("/xdr/public_api/v1/incidents/get_incidents/", "reply.incidents"),
        ("/xdr/public_api/v1/alerts/get_alerts_by_filter_data/", "reply.alerts"),
        ("/xdr/public_api/v1/endpoints/get_endpoint/", "reply.endpoints"),
    ):
        response = client.post(path, headers=headers,
                               json={"request_data": {"search_from": 0, "search_to": 200}})
        if response.status_code != 200:
            continue
        for record in dig(response.json(), where) or []:
            yield "xdr", path, record


def main():
    wanted = sys.argv[1:]
    types: dict[tuple[str, str], dict[str, set]] = {}
    notations: dict[tuple[str, str], dict[str, set]] = {}
    seen = 0

    for mount, path, record in records():
        if wanted and mount not in wanted:
            continue
        seen += 1
        for field, value in leaves(record):
            found = kind(value)
            if found is None:
                continue
            types.setdefault((mount, path, field), {}).setdefault(found, set()).add(path)
            if timeish(field):
                written = notation(value)
                if written:
                    notations.setdefault((mount, path, field), {}).setdefault(
                        written, set()).add(path)

    flags = []
    for (mount, route, field), kinds in sorted(types.items()):
        if len(kinds) > 1:
            flags.append((mount, "type", f"{field}  ({route})",
                          {k: sorted(v)[0] for k, v in kinds.items()}))
    for (mount, route, field), written in sorted(notations.items()):
        if len(written) > 1:
            flags.append((mount, "date", f"{field}  ({route})",
                          {k: sorted(v)[0] for k, v in written.items()}))

    print(f"=== TYPE STABILITY === {seen} record(s), {len(types)} field path(s)")
    by_mount = {}
    for mount, what, field, where in flags:
        by_mount.setdefault(mount, []).append((what, field, where))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for what, field, where in sorted(by_mount[mount]):
            print(f"  {what:<5} {field}")
            for value, route in sorted(where.items()):
                print(f"        {value:<22} first seen in {route}")
    print(f"\n  {len(flags)} field(s) that do not mean one thing")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
