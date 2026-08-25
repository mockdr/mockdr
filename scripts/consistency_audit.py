# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Fetch the same record two ways and check it is the same record.

Every product here serves a record from more than one route: a listing and a
fetch by id, a search and a document, an entity and the event a Splunk
add-on indexes for it. A client moves between them freely — it lists to find
an id, then fetches that id to act on it — and takes for granted that the
two describe the same thing.

A mock is unusually good at breaking that assumption, because each route
tends to be built separately: one path serialises a field and the other
computes it, one applies a projection the other does not, one reads the
record and the other a fixture. The result is a listing that says a host is
online and a fetch that says it is offline, with a 200 either way.

For each pair, every key the two answers share is compared by value. A key
only one of them carries is *not* a finding on its own: a listing is often a
narrower projection, and where the vendor says otherwise a comparator here
already checks it. What no vendor does is answer two different values for
the same field of the same record.

Exit status 1 when anything is flagged.

    backend/.venv/bin/python scripts/consistency_audit.py [mount ...]
"""

import base64
import json
import logging
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

ARM = ("/sentinel/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups"
       "/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-ws"
       "/providers/Microsoft.SecurityInsights")
API = {"api-version": "2024-03-01"}

#: Where the two views differ on purpose, because the product does. Kibana
#: fills a case's `comments` when the case is fetched by its id and leaves it
#: empty in `_find`, where `totalComment` says how many there are — measured
#: on 8.15, and imitated deliberately.
BY_DESIGN = frozenset({"comments"})

#: Values that are a property of *when* the answer was made rather than of the
#: record, and legitimately differ between two requests.
VOLATILE = frozenset({
    "updated", "updatedAt", "updated_at", "lastActiveDate", "lastLogin",
    "runDuration", "ttl", "eai:acl", "_score", "took", "query_time",
    "modification_time", "last_checkin", "diskUsage", "doneProgress",
})


def get(path, headers, **kwargs: object):
    response = client.get(path, headers=headers, **kwargs)
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def post(path, headers, body):
    response = client.post(path, headers=headers, json=body)
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def pairs():
    """Each ``(mount, what, listed, fetched)`` pair of views of one record."""
    # ── SentinelOne ────────────────────────────────────────────────────────
    headers = AUTH["web"]
    listing = (get("/web/api/v2.1/agents", headers, params={"limit": 1}) or {}).get("data")
    if listing:
        agent = listing[0]
        single = (get("/web/api/v2.1/agents", headers,
                      params={"ids": agent["id"]}) or {}).get("data")
        yield "web", f"agent {agent['id']}", agent, (single or [None])[0]
    listing = (get("/web/api/v2.1/threats", headers, params={"limit": 1}) or {}).get("data")
    if listing:
        threat = listing[0]
        single = (get("/web/api/v2.1/threats", headers,
                      params={"ids": threat["id"]}) or {}).get("data")
        yield "web", f"threat {threat['id']}", threat, (single or [None])[0]

    # ── CrowdStrike: the queries/entities pair, against combined ───────────
    headers = AUTH["cs"]
    combined = (get("/cs/devices/combined/host-groups/v1", headers,
                    params={"limit": 1}) or {}).get("resources")
    if combined:
        group = combined[0]
        entity = (get("/cs/devices/entities/host-groups/v1", headers,
                      params={"ids": group["id"]}) or {}).get("resources")
        yield "cs", f"host group {group['id']}", group, (entity or [None])[0]
    combined = (get("/cs/iocs/combined/indicator/v1", headers,
                    params={"limit": 1}) or {}).get("resources")
    if combined:
        ioc = combined[0]
        entity = (get("/cs/iocs/entities/indicators/v1", headers,
                      params={"ids": ioc["id"]}) or {}).get("resources")
        yield "cs", f"ioc {ioc['id']}", ioc, (entity or [None])[0]

    # ── Defender ───────────────────────────────────────────────────────────
    headers = AUTH["mde"]
    listing = (get("/mde/api/machines", headers, params={"$top": 1}) or {}).get("value")
    if listing:
        machine = listing[0]
        yield "mde", f"machine {machine['id']}", machine, get(
            f"/mde/api/machines/{machine['id']}", headers)
    listing = (get("/mde/api/alerts", headers, params={"$top": 1}) or {}).get("value")
    if listing:
        alert = listing[0]
        yield "mde", f"alert {alert['id']}", alert, get(
            f"/mde/api/alerts/{alert['id']}", headers)

    # ── Graph ──────────────────────────────────────────────────────────────
    headers = AUTH["graph"]
    for collection in ("security/alerts_v2", "security/incidents", "users",
                       "deviceManagement/managedDevices"):
        listing = (get(f"/graph/v1.0/{collection}", headers,
                       params={"$top": 1}) or {}).get("value")
        if listing:
            record = listing[0]
            yield "graph", f"{collection} {record.get('id')}", record, get(
                f"/graph/v1.0/{collection}/{record['id']}", headers)

    # ── Sentinel ───────────────────────────────────────────────────────────
    headers = AUTH["sentinel"]
    for collection in ("incidents", "bookmarks", "alertRules", "watchlists"):
        listing = (get(f"{ARM}/{collection}", headers, params=API) or {}).get("value")
        if listing:
            record = listing[0]
            yield "sentinel", f"{collection} {record.get('name')}", record, get(
                f"{ARM}/{collection}/{record['name']}", headers, params=API)

    # ── Cortex XDR ─────────────────────────────────────────────────────────
    headers = AUTH["xdr"]
    incidents = ((post("/xdr/public_api/v1/incidents/get_incidents/", headers,
                       {"request_data": {"search_from": 0, "search_to": 1}}) or {})
                 .get("reply", {}).get("incidents"))
    if incidents:
        incident = incidents[0]
        extra = (post("/xdr/public_api/v1/incidents/get_incident_extra_data/", headers,
                      {"request_data": {"incident_id": str(incident["incident_id"])}})
                 or {}).get("reply", {}).get("incident")
        yield "xdr", f"incident {incident['incident_id']}", incident, extra

    # ── Kibana ─────────────────────────────────────────────────────────────
    headers = AUTH["kibana"]
    found = (get("/kibana/api/cases/_find", headers, params={"perPage": 1}) or {}).get("cases")
    if found:
        case = found[0]
        yield "kibana", f"case {case['id']}", case, get(
            f"/kibana/api/cases/{case['id']}", headers)
    found = (get("/kibana/api/detection_engine/rules/_find", headers,
                 params={"per_page": 1}) or {}).get("data")
    if found:
        rule = found[0]
        yield "kibana", f"rule {rule['id']}", rule, get(
            "/kibana/api/detection_engine/rules", headers, params={"id": rule["id"]})

    # ── Elasticsearch: a search hit against the document ───────────────────
    headers = AUTH["elastic"]
    hits = ((post("/elastic/logs-endpoint/_search", headers, {"size": 1}) or {})
            .get("hits", {}).get("hits"))
    if hits:
        hit = hits[0]
        document = get(f"/elastic/logs-endpoint/_doc/{hit['_id']}", headers)
        yield ("elastic", f"document {hit['_id']}", hit.get("_source"),
               (document or {}).get("_source"))

    # ── Splunk: the collection against the single entry ────────────────────
    headers = AUTH["splunk"]
    for collection in ("saved/searches", "data/indexes", "authentication/users"):
        listing = (get(f"/splunk/services/{collection}", headers,
                       params={"output_mode": "json", "count": 1}) or {}).get("entry")
        if listing:
            entry = listing[0]
            single = (get(f"/splunk/services/{collection}/{entry['name']}", headers,
                          params={"output_mode": "json"}) or {}).get("entry")
            yield ("splunk", f"{collection} {entry['name']}", entry,
                   (single or [None])[0])


def differences(listed, fetched, path=""):
    """Every shared key whose value differs, deepest first."""
    if isinstance(listed, dict) and isinstance(fetched, dict):
        out = []
        for key in sorted(set(listed) & set(fetched)):
            if key in VOLATILE or key in BY_DESIGN:
                continue
            out += differences(listed[key], fetched[key], f"{path}.{key}" if path else key)
        return out
    if isinstance(listed, list) and isinstance(fetched, list):
        if len(listed) != len(fetched):
            return [(path, f"{len(listed)} item(s)", f"{len(fetched)} item(s)")]
        out = []
        for index, (one, other) in enumerate(zip(listed, fetched, strict=True)):
            out += differences(one, other, f"{path}[{index}]")
        return out
    if listed != fetched:
        return [(path, listed, fetched)]
    return []


def main():
    wanted = sys.argv[1:]
    flags, checked = [], 0
    for mount, what, listed, fetched in pairs():
        if wanted and mount not in wanted:
            continue
        checked += 1
        if listed is None or fetched is None:
            flags.append((mount, what, "(one of the two routes did not answer)", "", ""))
            continue
        for where, one, other in differences(listed, fetched):
            flags.append((mount, what, where, one, other))

    print(f"=== CROSS-ROUTE CONSISTENCY === {checked} record(s) fetched two ways")
    by_mount = {}
    for mount, what, where, one, other in flags:
        by_mount.setdefault(mount, []).append((what, where, one, other))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for what, where, one, other in sorted(by_mount[mount], key=lambda r: (r[0], r[1])):
            print(f"  {what}\n      {where}: listed {json.dumps(one)[:60]} "
                  f"!= fetched {json.dumps(other)[:60]}")
    print(f"\n  {len(flags)} field(s) that answer differently depending on the route")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
