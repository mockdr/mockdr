# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201, PLR0915
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Write something, then ask the mock to hand it back.

Every other audit in this directory reads. This one writes first, because a
mock can answer each single request plausibly and still forget what it was
told: a create that drops half the body and returns defaults, an update that
answers 200 and changes nothing, a delete that answers 200 and leaves the
record in the listing. All three are 200s. A client sees nothing wrong until
the next request, and a client that never re-reads never sees it at all.

Each cycle asserts what a client is entitled to assume:

* **echo** — a field sent in the body comes back in the answer with the
  value that was sent, not a default;
* **read-back** — the record fetched by its own id carries that value too;
* **listed** — the record appears in the collection it belongs to;
* **update** — a changed field reads back changed;
* **delete** — the record is gone from both the item route and the listing.

A cycle whose vendor does not publish one of those steps simply omits it.
Every cycle writes under a `zzz-` name and deletes what it made, but the
process holds the mock's state in memory anyway, so a run leaves no trace.

    backend/.venv/bin/python scripts/roundtrip_audit.py [mount ...]
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
    token = response.json().get("access_token")
    return {"Authorization": f"Bearer {token}"}


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
    "splunk": {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()},
    "elastic": {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()},
    "kibana": {
        "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
        "kbn-xsrf": "true",
    },
}

CYCLES = []


def cycle(mount, name):
    def register(function):
        CYCLES.append((mount, name, function))
        return function
    return register


class Check:
    """The findings of one cycle, and the vocabulary to state them."""

    def __init__(self, mount: str, name: str) -> None:
        """Start a cycle with nothing found yet."""
        self.mount, self.name, self.findings = mount, name, []
        self.headers = AUTH[mount]

    # ── requests ────────────────────────────────────────────────────────────
    def request(self, method, path, expect=(200, 201), **kwargs: object):
        """Send one request, failing the cycle if the status is unexpected."""
        headers = {**self.headers, **kwargs.pop("headers", {})}
        response = client.request(method, path, headers=headers, **kwargs)
        if expect and response.status_code not in expect:
            self.fail(f"{method} {path}", f"answered {response.status_code}, "
                                          f"expected {'/'.join(map(str, expect))}: "
                                          f"{response.text[:120]}")
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    def get(self, path, **kwargs: object):
        """Read, with the same expectations as any other request."""
        return self.request("GET", path, **kwargs)

    # ── assertions ──────────────────────────────────────────────────────────
    def fail(self, where, what):
        """Record one finding: where it was seen, and what was wrong."""
        self.findings.append((where, what))

    def echoes(self, where, sent, got):
        """Every field sent came back carrying the value that was sent."""
        if not isinstance(got, dict):
            self.fail(where, f"answered {type(got).__name__}, not an object")
            return
        for field, value in sent.items():
            if field not in got:
                self.fail(where, f"dropped {field!r} — sent {value!r}, not in the answer")
            elif got[field] != value:
                self.fail(where, f"changed {field!r} — sent {value!r}, got {got[field]!r}")

    def carries(self, where, record, field, value):
        """One field of a record holds the value it should."""
        if not isinstance(record, dict):
            self.fail(where, f"answered {type(record).__name__}, not an object")
        elif record.get(field) != value:
            self.fail(where, f"{field!r} is {record.get(field)!r}, expected {value!r}")

    def listed(self, where, items, key, value, *, present=True):
        """A record is in the collection it belongs to — or is gone from it."""
        if items is None:
            self.fail(where, "the listing carried no collection")
            return
        found = any(isinstance(i, dict) and str(i.get(key)) == str(value) for i in items)
        if found is not present:
            self.fail(where, f"{key}={value} is {'missing from' if present else 'still in'}"
                             f" the listing of {len(items)} record(s)")


def find(body, *keys: object):
    """Follow a path of keys through an envelope, tolerating a missing step."""
    for key in keys:
        if isinstance(body, dict):
            body = body.get(key)
        elif isinstance(body, list) and isinstance(key, int) and len(body) > key:
            body = body[key]
        else:
            return None
    return body


# ── SentinelOne ─────────────────────────────────────────────────────────────

@cycle("web", "groups")
def s1_groups(check):
    sent = {"name": "zzz-audit-group", "siteId": "1", "inherits": True}
    created = find(check.request("POST", "/web/api/v2.1/groups", json={"data": sent}), "data")
    if not created:
        return
    check.echoes("POST /groups", sent | {"siteId": created.get("siteId")}, created)
    group = created["id"]
    check.carries("GET /groups/{id}", find(check.get(f"/web/api/v2.1/groups/{group}"), "data"),
                  "name", "zzz-audit-group")
    check.listed("GET /groups", find(check.get("/web/api/v2.1/groups"), "data"), "id", group)
    check.request("PUT", f"/web/api/v2.1/groups/{group}",
                  json={"data": {"name": "zzz-audit-renamed"}})
    check.carries("GET /groups/{id} after PUT",
                  find(check.get(f"/web/api/v2.1/groups/{group}"), "data"),
                  "name", "zzz-audit-renamed")
    check.request("DELETE", f"/web/api/v2.1/groups/{group}")
    check.get(f"/web/api/v2.1/groups/{group}", expect=(404,))
    check.listed("GET /groups after DELETE", find(check.get("/web/api/v2.1/groups"), "data"),
                 "id", group, present=False)


@cycle("web", "sites")
def s1_sites(check):
    account = find(check.get("/web/api/v2.1/accounts"), "data", 0, "id")
    sent = {"name": "zzz-audit-site", "accountId": account, "siteType": "Trial",
            "suite": "Core", "totalLicenses": 7, "description": "audit"}
    created = find(check.request("POST", "/web/api/v2.1/sites", json={"data": sent}), "data")
    if not created:
        return
    check.echoes("POST /sites", sent, created)
    site = created["id"]
    check.carries("GET /sites/{id}", find(check.get(f"/web/api/v2.1/sites/{site}"), "data"),
                  "totalLicenses", 7)
    check.listed("GET /sites", find(check.get("/web/api/v2.1/sites"), "data", "sites"),
                 "id", site)
    check.request("PUT", f"/web/api/v2.1/sites/{site}",
                  json={"data": {"name": "zzz-audit-site-renamed"}})
    check.carries("GET /sites/{id} after PUT",
                  find(check.get(f"/web/api/v2.1/sites/{site}"), "data"),
                  "name", "zzz-audit-site-renamed")
    check.request("DELETE", f"/web/api/v2.1/sites/{site}")
    check.listed("GET /sites after DELETE",
                 find(check.get("/web/api/v2.1/sites"), "data", "sites"), "id", site,
                 present=False)


@cycle("web", "users")
def s1_users(check):
    sent = {"fullName": "ZZZ Audit", "email": "zzz-audit@example.test"}
    created = find(check.request("POST", "/web/api/v2.1/users", json={"data": sent}), "data")
    if not created:
        return
    check.echoes("POST /users", sent, created)
    user = created["id"]
    check.carries("GET /users/{id}", find(check.get(f"/web/api/v2.1/users/{user}"), "data"),
                  "email", "zzz-audit@example.test")
    check.listed("GET /users", find(check.get("/web/api/v2.1/users"), "data"), "id", user)
    check.request("PUT", f"/web/api/v2.1/users/{user}",
                  json={"data": {"fullName": "ZZZ Audit Renamed"}})
    check.carries("GET /users/{id} after PUT",
                  find(check.get(f"/web/api/v2.1/users/{user}"), "data"),
                  "fullName", "ZZZ Audit Renamed")
    check.request("DELETE", f"/web/api/v2.1/users/{user}")
    check.get(f"/web/api/v2.1/users/{user}", expect=(404,))


# ── CrowdStrike Falcon ──────────────────────────────────────────────────────

@cycle("cs", "host-groups")
def cs_host_groups(check):
    sent = {"name": "zzz-audit-hostgroup", "description": "audit",
            "group_type": "static"}
    created = find(check.request("POST", "/cs/devices/entities/host-groups/v1",
                                 json={"resources": [sent]}), "resources", 0)
    if not created:
        return
    check.echoes("POST /host-groups", sent, created)
    group = created["id"]
    check.carries("GET /host-groups?ids=",
                  find(check.get("/cs/devices/entities/host-groups/v1",
                                 params={"ids": group}), "resources", 0),
                  "name", "zzz-audit-hostgroup")
    check.listed("GET /host-group-ids",
                 [{"id": i} for i in
                  find(check.get("/cs/devices/queries/host-groups/v1"), "resources") or []],
                 "id", group)
    check.request("PATCH", "/cs/devices/entities/host-groups/v1",
                  json={"resources": [{"id": group, "description": "audit-changed"}]})
    check.carries("GET /host-groups after PATCH",
                  find(check.get("/cs/devices/entities/host-groups/v1",
                                 params={"ids": group}), "resources", 0),
                  "description", "audit-changed")
    check.request("DELETE", "/cs/devices/entities/host-groups/v1", params={"ids": group})
    check.listed("GET /host-group-ids after DELETE",
                 [{"id": i} for i in
                  find(check.get("/cs/devices/queries/host-groups/v1"), "resources") or []],
                 "id", group, present=False)


@cycle("cs", "iocs")
def cs_iocs(check):
    sent = {"type": "domain", "value": "zzz-audit.example.test", "action": "no_action",
            "severity": "low", "description": "audit", "platforms": ["windows"]}
    created = find(check.request("POST", "/cs/iocs/entities/indicators/v1",
                                 json={"indicators": [sent]}), "resources", 0)
    if not created:
        return
    check.echoes("POST /iocs", sent, created)
    ioc = created["id"]
    check.carries("GET /iocs?ids=",
                  find(check.get("/cs/iocs/entities/indicators/v1",
                                 params={"ids": ioc}), "resources", 0),
                  "value", "zzz-audit.example.test")
    check.request("PATCH", "/cs/iocs/entities/indicators/v1",
                  json={"indicators": [{"id": ioc, "description": "audit-changed"}]})
    check.carries("GET /iocs after PATCH",
                  find(check.get("/cs/iocs/entities/indicators/v1",
                                 params={"ids": ioc}), "resources", 0),
                  "description", "audit-changed")
    check.request("DELETE", "/cs/iocs/entities/indicators/v1", params={"ids": ioc})
    check.listed("GET /iocs after DELETE",
                 find(check.get("/cs/iocs/entities/indicators/v1",
                                 params={"ids": ioc}, expect=None), "resources"),
                 "id", ioc, present=False)


@cycle("cs", "alerts")
def cs_alerts(check):
    alert = find(check.get("/cs/alerts/queries/alerts/v2", params={"limit": 1}),
                 "resources", 0)
    if not alert:
        return
    check.request("PATCH", "/cs/alerts/entities/alerts/v3", json={
        "composite_ids": [alert],
        "action_parameters": [{"name": "update_status", "value": "in_progress"}],
    })
    check.carries("POST /alerts/entities/alerts/v2 after PATCH",
                  find(check.request("POST", "/cs/alerts/entities/alerts/v2",
                                     json={"composite_ids": [alert]}), "resources", 0),
                  "status", "in_progress")


# ── Defender for Endpoint ───────────────────────────────────────────────────

@cycle("mde", "indicators")
def mde_indicators(check):
    sent = {"indicatorValue": "zzz-audit.example.test", "indicatorType": "DomainName",
            "action": "Alert", "title": "zzz-audit", "severity": "Medium",
            "description": "audit", "recommendedActions": "none"}
    created = check.request("POST", "/mde/api/indicators", json=sent)
    if not isinstance(created, dict) or "id" not in created:
        return
    check.echoes("POST /indicators", sent, created)
    indicator = created["id"]
    # No read-back by id: Defender publishes List, Submit, Import, Delete and
    # BatchDelete for indicators, and no route to fetch one. The listing is
    # the only way back to it, so that is what a client would do.
    check.listed("GET /indicators", find(check.get("/mde/api/indicators"), "value"),
                 "id", indicator)
    check.carries("GET /indicators",
                  next((i for i in find(check.get("/mde/api/indicators"), "value") or []
                        if i.get("id") == indicator), None),
                  "indicatorValue", "zzz-audit.example.test")
    check.request("DELETE", f"/mde/api/indicators/{indicator}", expect=(200, 204))
    check.listed("GET /indicators after DELETE",
                 find(check.get("/mde/api/indicators"), "value"), "id", indicator,
                 present=False)


@cycle("mde", "alerts")
def mde_alerts(check):
    alert = find(check.get("/mde/api/alerts", params={"$top": 1}), "value", 0, "id")
    if not alert:
        return
    check.request("PATCH", f"/mde/api/alerts/{alert}",
                  json={"status": "InProgress", "classification": "TruePositive",
                        "determination": "Malware", "comment": "zzz-audit"})
    check.carries("GET /alerts/{id} after PATCH", check.get(f"/mde/api/alerts/{alert}"),
                  "status", "InProgress")
    check.carries("GET /alerts/{id} after PATCH", check.get(f"/mde/api/alerts/{alert}"),
                  "determination", "Malware")


# ── Microsoft Graph ─────────────────────────────────────────────────────────

@cycle("graph", "tiIndicators")
def graph_ti(check):
    sent = {"action": "alert", "description": "zzz-audit", "domainName": "zzz-audit.example.test",
            "expirationDateTime": "2030-01-01T00:00:00Z", "targetProduct": "Azure Sentinel",
            "threatType": "WatchList", "tlpLevel": "amber", "confidence": 42,
            "severity": 3, "killChain": ["Delivery"], "malwareFamilyNames": ["Emotet"],
            "tags": ["zzz-audit"], "passiveOnly": False, "externalId": "zzz-1"}
    created = check.request("POST", "/graph/v1.0/security/tiIndicators", json=sent)
    if not isinstance(created, dict) or "id" not in created:
        return
    check.echoes("POST /tiIndicators", sent, created)
    check.carries("POST /tiIndicators", created, "isActive", True)
    indicator = created["id"]
    check.listed("GET /tiIndicators", find(check.get("/graph/v1.0/security/tiIndicators"),
                                           "value"), "id", indicator)
    check.request("DELETE", f"/graph/v1.0/security/tiIndicators/{indicator}",
                  expect=(200, 204))
    check.listed("GET /tiIndicators after DELETE",
                 find(check.get("/graph/v1.0/security/tiIndicators"), "value"),
                 "id", indicator, present=False)


@cycle("graph", "alerts_v2")
def graph_alerts(check):
    alert = find(check.get("/graph/v1.0/security/alerts_v2", params={"$top": 1}),
                 "value", 0, "id")
    if not alert:
        return
    check.request("PATCH", f"/graph/v1.0/security/alerts_v2/{alert}",
                  json={"status": "inProgress", "classification": "truePositive",
                        "determination": "malware", "assignedTo": "zzz-audit"})
    after = check.get(f"/graph/v1.0/security/alerts_v2/{alert}")
    check.carries("GET /alerts_v2/{id} after PATCH", after, "status", "inProgress")
    check.carries("GET /alerts_v2/{id} after PATCH", after, "assignedTo", "zzz-audit")
    check.carries("GET /alerts_v2/{id} after PATCH", after, "determination", "malware")


# ── Microsoft Sentinel ──────────────────────────────────────────────────────

ARM = ("/sentinel/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups"
       "/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-ws"
       "/providers/Microsoft.SecurityInsights")
API = {"api-version": "2024-03-01"}


@cycle("sentinel", "bookmarks")
def sentinel_bookmarks(check):
    name = "00000000-0000-0000-0000-0000000000b1"
    sent = {"displayName": "zzz-audit-bookmark", "query": "SecurityEvent | take 1",
            "notes": "audit", "labels": ["zzz-audit"]}
    created = check.request("PUT", f"{ARM}/bookmarks/{name}", params=API,
                            json={"properties": sent})
    if not isinstance(created, dict):
        return
    check.echoes("PUT /bookmarks/{name}", sent, created.get("properties"))
    check.carries("GET /bookmarks/{name}",
                  find(check.get(f"{ARM}/bookmarks/{name}", params=API), "properties"),
                  "displayName", "zzz-audit-bookmark")
    check.listed("GET /bookmarks", find(check.get(f"{ARM}/bookmarks", params=API), "value"),
                 "name", name)
    check.request("PUT", f"{ARM}/bookmarks/{name}", params=API,
                  json={"properties": sent | {"notes": "audit-changed"}})
    check.carries("GET /bookmarks/{name} after PUT",
                  find(check.get(f"{ARM}/bookmarks/{name}", params=API), "properties"),
                  "notes", "audit-changed")
    check.request("DELETE", f"{ARM}/bookmarks/{name}", params=API, expect=(200, 204))
    check.get(f"{ARM}/bookmarks/{name}", params=API, expect=(404,))
    check.listed("GET /bookmarks after DELETE",
                 find(check.get(f"{ARM}/bookmarks", params=API), "value"),
                 "name", name, present=False)


@cycle("sentinel", "watchlists")
def sentinel_watchlists(check):
    alias = "zzz-audit-watchlist"
    sent = {"displayName": "zzz-audit", "provider": "Mockdr", "source": "Local file",
            "description": "audit", "itemsSearchKey": "IPAddress"}
    created = check.request("PUT", f"{ARM}/watchlists/{alias}", params=API,
                            json={"properties": sent})
    if not isinstance(created, dict):
        return
    check.echoes("PUT /watchlists/{alias}", sent, created.get("properties"))
    check.listed("GET /watchlists", find(check.get(f"{ARM}/watchlists", params=API), "value"),
                 "name", alias)
    item = "00000000-0000-0000-0000-0000000000c1"
    item_sent = {"itemsKeyValue": {"IPAddress": "203.0.113.7", "Note": "zzz-audit"}}
    made = check.request("PUT", f"{ARM}/watchlists/{alias}/watchlistItems/{item}",
                         params=API, json={"properties": item_sent})
    if isinstance(made, dict):
        check.echoes("PUT /watchlistItems/{id}", item_sent, made.get("properties"))
        check.listed("GET /watchlistItems",
                     find(check.get(f"{ARM}/watchlists/{alias}/watchlistItems",
                                    params=API), "value"), "name", item)
        check.request("DELETE", f"{ARM}/watchlists/{alias}/watchlistItems/{item}",
                      params=API, expect=(200, 204))
    check.request("DELETE", f"{ARM}/watchlists/{alias}", params=API, expect=(200, 204))
    check.listed("GET /watchlists after DELETE",
                 find(check.get(f"{ARM}/watchlists", params=API), "value"),
                 "name", alias, present=False)


@cycle("sentinel", "incidents")
def sentinel_incidents(check):
    incident = find(check.get(f"{ARM}/incidents", params=API), "value", 0)
    if not incident:
        return
    name = incident["name"]
    properties = dict(incident.get("properties") or {})
    sent = {**properties, "status": "Active", "severity": "High",
            "title": "zzz-audit-title", "description": "audit"}
    check.request("PUT", f"{ARM}/incidents/{name}", params=API, json={"properties": sent})
    after = find(check.get(f"{ARM}/incidents/{name}", params=API), "properties")
    check.carries("GET /incidents/{name} after PUT", after, "title", "zzz-audit-title")
    check.carries("GET /incidents/{name} after PUT", after, "severity", "High")
    comment = "00000000-0000-0000-0000-0000000000d1"
    made = check.request("PUT", f"{ARM}/incidents/{name}/comments/{comment}", params=API,
                         json={"properties": {"message": "zzz-audit-comment"}})
    if isinstance(made, dict):
        check.carries("PUT /comments/{id}", made.get("properties"),
                      "message", "zzz-audit-comment")
        check.listed("GET /comments",
                     find(check.get(f"{ARM}/incidents/{name}/comments", params=API), "value"),
                     "name", comment)
        check.request("DELETE", f"{ARM}/incidents/{name}/comments/{comment}", params=API,
                      expect=(200, 204))
        check.listed("GET /comments after DELETE",
                     find(check.get(f"{ARM}/incidents/{name}/comments", params=API), "value"),
                     "name", comment, present=False)


@cycle("sentinel", "threat-intelligence")
def sentinel_indicators(check):
    sent = {"displayName": "zzz-audit-indicator", "pattern": "[domain-name:value = 'zzz.test']",
            "patternType": "domain-name", "threatTypes": ["malicious-activity"],
            "confidence": 42, "source": "mockdr", "description": "audit"}
    created = check.request("POST", f"{ARM}/threatIntelligence/main/createIndicator",
                            params=API, json={"properties": sent})
    if not isinstance(created, dict) or not created.get("name"):
        return
    check.echoes("POST /createIndicator", sent, created.get("properties"))
    name = created["name"]
    check.carries("GET /indicators/{name}",
                  find(check.get(f"{ARM}/threatIntelligence/main/indicators/{name}",
                                 params=API), "properties"),
                  "displayName", "zzz-audit-indicator")
    check.listed("POST /queryIndicators",
                 find(check.request("POST", f"{ARM}/threatIntelligence/main/queryIndicators",
                                    params=API, json={"pageSize": 500}), "value"),
                 "name", name)
    check.request("POST", f"{ARM}/threatIntelligence/main/indicators/appendTags",
                  params=API, json={"threatIntelligenceTags": ["zzz-audit-tag"]},
                  expect=(200, 204, 400, 404))
    check.request("DELETE", f"{ARM}/threatIntelligence/main/indicators/{name}",
                  params=API, expect=(200, 204))
    check.get(f"{ARM}/threatIntelligence/main/indicators/{name}", params=API, expect=(404,))


# ── Cortex XDR ──────────────────────────────────────────────────────────────

@cycle("xdr", "hash-exceptions")
def xdr_hash_exceptions(check):
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # Cortex publishes no route that reads the lists back — the four routes
    # are add and remove for each of the two — so the round trip stops at the
    # documented body being accepted and the documented reply coming back.
    for route in ("allowlist", "blocklist"):
        for suffix in ("/", "/remove/"):
            reply = check.request(
                "POST", f"/xdr/public_api/v1/hash_exceptions/{route}{suffix}",
                json={"request_data": {"hash_list": [digest], "comment": "zzz-audit",
                                       "incident_id": 1}})
            if reply is not None and find(reply, "reply") not in (True, 1):
                check.fail(f"POST /hash_exceptions/{route}{suffix}",
                           f"reply is {find(reply, 'reply')!r}, expected true")


@cycle("xdr", "endpoint-name")
def xdr_endpoint_name(check):
    endpoint = find(check.request("POST", "/xdr/public_api/v1/endpoints/get_endpoint/",
                                  json={"request_data": {"search_from": 0, "search_to": 1}}),
                    "reply", "endpoints", 0)
    if not endpoint:
        return
    endpoint_id = endpoint.get("endpoint_id")
    check.request("POST", "/xdr/public_api/v1/endpoints/update_agent_name/", json={
        "request_data": {"filters": [{"field": "endpoint_id_list", "operator": "in",
                                      "value": [endpoint_id]}],
                         "alias": "zzz-audit-endpoint"}})
    after = find(check.request("POST", "/xdr/public_api/v1/endpoints/get_endpoint/", json={
        "request_data": {"filters": [{"field": "endpoint_id_list", "operator": "in",
                                      "value": [endpoint_id]}]}}), "reply", "endpoints", 0)
    check.carries("POST /endpoints/get_endpoint/ after update_agent_name",
                  after, "alias", "zzz-audit-endpoint")


@cycle("xdr", "incidents")
def xdr_incidents(check):
    incident = find(check.request("POST", "/xdr/public_api/v1/incidents/get_incidents/",
                                  json={"request_data": {"search_from": 0, "search_to": 1}}),
                    "reply", "incidents", 0)
    if not incident:
        return
    incident_id = str(incident.get("incident_id"))
    check.request("POST", "/xdr/public_api/v1/incidents/update_incident/", json={
        "request_data": {"incident_id": incident_id,
                         "update_data": {"status": "under_investigation",
                                         "manual_severity": "high"}}})
    after = find(check.request("POST", "/xdr/public_api/v1/incidents/get_incident_extra_data/",
                               json={"request_data": {"incident_id": incident_id}}),
                 "reply", "incident")
    check.carries("get_incident_extra_data after update_incident",
                  after, "status", "under_investigation")
    check.carries("get_incident_extra_data after update_incident",
                  after, "manual_severity", "high")


@cycle("xdr", "agent-tags")
def xdr_tags(check):
    endpoint = find(check.request("POST", "/xdr/public_api/v1/endpoints/get_endpoint/",
                                  json={"request_data": {"search_from": 0, "search_to": 1}}),
                    "reply", "endpoints", 0)
    if not endpoint:
        return
    endpoint_id = endpoint.get("endpoint_id")
    where = {"filters": [{"field": "endpoint_id_list", "operator": "in",
                          "value": [endpoint_id]}]}
    check.request("POST", "/xdr/public_api/v1/tags/agents/assign/",
                  json={"request_data": {**where, "tag": "zzz-audit-tag"}})
    after = find(check.request("POST", "/xdr/public_api/v1/endpoints/get_endpoint/",
                               json={"request_data": where}), "reply", "endpoints", 0)
    tags = ((after or {}).get("endpointTags") or "").split(",")
    if "zzz-audit-tag" not in tags:
        check.fail("POST /tags/agents/assign/", f"the tag is not on the endpoint: {tags!r}")
    check.request("POST", "/xdr/public_api/v1/tags/agents/remove/",
                  json={"request_data": {**where, "tag": "zzz-audit-tag"}})
    after = find(check.request("POST", "/xdr/public_api/v1/endpoints/get_endpoint/",
                               json={"request_data": where}), "reply", "endpoints", 0)
    if "zzz-audit-tag" in ((after or {}).get("endpointTags") or "").split(","):
        check.fail("POST /tags/agents/remove/", "the tag is still on the endpoint")


# ── Splunk ──────────────────────────────────────────────────────────────────

FORM = {"Content-Type": "application/x-www-form-urlencoded"}
JSON_OUT = {"output_mode": "json"}


@cycle("splunk", "saved-searches")
def splunk_saved_searches(check):
    name = "zzz-audit-search"
    check.request("POST", "/splunk/services/saved/searches", params=JSON_OUT, headers=FORM,
                  data={"name": name, "search": "index=main | head 1",
                        "description": "audit", "is_scheduled": "0"},
                  expect=(200, 201))
    entry = find(check.get(f"/splunk/services/saved/searches/{name}", params=JSON_OUT),
                 "entry", 0)
    check.carries("GET /saved/searches/{name}", find(entry, "content"),
                  "search", "index=main | head 1")
    check.listed("GET /saved/searches",
                 find(check.get("/splunk/services/saved/searches",
                                params=JSON_OUT | {"count": "0"}), "entry"), "name", name)
    check.request("POST", f"/splunk/services/saved/searches/{name}", params=JSON_OUT,
                  headers=FORM, data={"search": "index=main | head 2"})
    check.carries("GET /saved/searches/{name} after POST",
                  find(check.get(f"/splunk/services/saved/searches/{name}",
                                 params=JSON_OUT), "entry", 0, "content"),
                  "search", "index=main | head 2")
    check.request("DELETE", f"/splunk/services/saved/searches/{name}", params=JSON_OUT)
    check.get(f"/splunk/services/saved/searches/{name}", params=JSON_OUT, expect=(404,))
    check.listed("GET /saved/searches after DELETE",
                 find(check.get("/splunk/services/saved/searches",
                                params=JSON_OUT | {"count": "0"}), "entry"),
                 "name", name, present=False)


@cycle("splunk", "kvstore")
def splunk_kvstore(check):
    base = "/splunk/servicesNS/nobody/search/storage/collections/data/zzz_audit_collection"
    check.request("POST", "/splunk/servicesNS/nobody/search/storage/collections/config",
                  params=JSON_OUT, headers=FORM, data={"name": "zzz_audit_collection"},
                  expect=(200, 201, 404, 409))
    made = check.request("POST", base, json={"_key": "zzz1", "name": "audit", "score": 7},
                         expect=(200, 201))
    if not isinstance(made, dict):
        return
    check.carries("POST /storage/collections/data", made, "_key", "zzz1")
    record = check.get(f"{base}/zzz1")
    check.carries("GET /storage/collections/data/{key}", record, "name", "audit")
    check.carries("GET /storage/collections/data/{key}", record, "score", 7)
    check.listed("GET /storage/collections/data", check.get(base), "_key", "zzz1")
    check.request("POST", f"{base}/zzz1", json={"_key": "zzz1", "name": "audit-changed",
                                                "score": 9})
    check.carries("GET /{key} after POST", check.get(f"{base}/zzz1"),
                  "name", "audit-changed")
    check.request("DELETE", f"{base}/zzz1", expect=(200, 204))
    check.get(f"{base}/zzz1", expect=(404,))
    check.listed("GET /storage/collections/data after DELETE", check.get(base),
                 "_key", "zzz1", present=False)


@cycle("splunk", "indexes")
def splunk_indexes(check):
    name = "zzz_audit_index"
    check.request("POST", "/splunk/services/data/indexes", params=JSON_OUT, headers=FORM,
                  data={"name": name, "maxTotalDataSizeMB": "12345"}, expect=(200, 201))
    entry = find(check.get(f"/splunk/services/data/indexes/{name}", params=JSON_OUT),
                 "entry", 0)
    # splunkd answers this one as a number, whatever the form sent.
    check.carries("GET /data/indexes/{name}", find(entry, "content"),
                  "maxTotalDataSizeMB", 12345)
    check.request("POST", f"/splunk/services/data/indexes/{name}", params=JSON_OUT,
                  headers=FORM, data={"maxTotalDataSizeMB": "777"})
    check.carries("GET /data/indexes/{name} after POST",
                  find(check.get(f"/splunk/services/data/indexes/{name}",
                                 params=JSON_OUT), "entry", 0, "content"),
                  "maxTotalDataSizeMB", 777)
    check.request("POST", "/splunk/services/data/indexes", params=JSON_OUT, headers=FORM,
                  data={"name": "zzz_audit_reject", "zzzNotAThing": "1"}, expect=(400,))
    check.listed("GET /data/indexes",
                 find(check.get("/splunk/services/data/indexes",
                                params=JSON_OUT | {"count": "0"}), "entry"), "name", name)
    check.request("DELETE", f"/splunk/services/data/indexes/{name}", params=JSON_OUT)
    check.listed("GET /data/indexes after DELETE",
                 find(check.get("/splunk/services/data/indexes",
                                params=JSON_OUT | {"count": "0"}), "entry"),
                 "name", name, present=False)


# ── Elasticsearch ───────────────────────────────────────────────────────────

@cycle("elastic", "documents")
def elastic_documents(check):
    index = "zzz-audit-index"
    check.request("PUT", f"/elastic/{index}", json={
        "mappings": {"properties": {"name": {"type": "keyword"}, "score": {"type": "long"}}},
    }, expect=(200, 201))
    body = {"name": "audit", "score": 7}
    made = check.request("PUT", f"/elastic/{index}/_doc/zzz1", params={"refresh": "true"},
                         json=body, expect=(200, 201))
    check.carries("PUT /{index}/_doc/{id}", made, "result", "created")
    got = check.get(f"/elastic/{index}/_doc/zzz1")
    check.carries("GET /{index}/_doc/{id}", got, "found", True)
    check.echoes("GET /{index}/_doc/{id}", body, find(got, "_source"))
    hits = find(check.request("POST", f"/elastic/{index}/_search",
                              json={"query": {"term": {"name": "audit"}}}), "hits", "hits")
    check.listed("POST /{index}/_search", hits, "_id", "zzz1")
    check.request("POST", f"/elastic/{index}/_update/zzz1", params={"refresh": "true"},
                  json={"doc": {"score": 9}})
    check.carries("GET /{index}/_doc/{id} after _update",
                  find(check.get(f"/elastic/{index}/_doc/zzz1"), "_source"), "score", 9)
    check.request("DELETE", f"/elastic/{index}/_doc/zzz1", params={"refresh": "true"})
    check.get(f"/elastic/{index}/_doc/zzz1", expect=(404,))
    empty = find(check.request("POST", f"/elastic/{index}/_search",
                               json={"query": {"term": {"name": "audit"}}}), "hits", "hits")
    check.listed("POST /{index}/_search after DELETE", empty, "_id", "zzz1", present=False)
    check.request("DELETE", f"/elastic/{index}")
    check.get(f"/elastic/{index}", expect=(404,))


# ── Kibana ──────────────────────────────────────────────────────────────────

@cycle("kibana", "cases")
def kibana_cases(check):
    sent = {"title": "zzz-audit-case", "description": "audit",
            "tags": ["zzz-audit"],
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
            "settings": {"syncAlerts": False},
            "owner": "securitySolution"}
    created = check.request("POST", "/kibana/api/cases", json=sent)
    if not isinstance(created, dict) or "id" not in created:
        return
    check.echoes("POST /api/cases", {k: sent[k] for k in ("title", "description", "tags")},
                 created)
    case = created["id"]
    check.carries("GET /api/cases/{id}", check.get(f"/kibana/api/cases/{case}"),
                  "title", "zzz-audit-case")
    check.listed("GET /api/cases/_find",
                 find(check.get("/kibana/api/cases/_find", params={"perPage": "100"}),
                      "cases"), "id", case)
    check.request("PATCH", "/kibana/api/cases", json={"cases": [
        {"id": case, "version": created.get("version"), "title": "zzz-audit-renamed"}]})
    check.carries("GET /api/cases/{id} after PATCH",
                  check.get(f"/kibana/api/cases/{case}"), "title", "zzz-audit-renamed")
    comment = check.request("POST", f"/kibana/api/cases/{case}/comments",
                            json={"type": "user", "comment": "zzz-audit-comment",
                                  "owner": "securitySolution"})
    if isinstance(comment, dict):
        found = [c for c in (comment.get("comments") or [])
                 if c.get("comment") == "zzz-audit-comment"]
        if not found:
            check.fail("POST /api/cases/{id}/comments",
                       "the comment is not in the case it was added to")
    check.request("DELETE", "/kibana/api/cases", params={"ids": json.dumps([case])},
                  expect=(200, 204))
    check.get(f"/kibana/api/cases/{case}", expect=(404,))
    check.listed("GET /api/cases/_find after DELETE",
                 find(check.get("/kibana/api/cases/_find", params={"perPage": "100"}),
                      "cases"), "id", case, present=False)


@cycle("kibana", "detection-rules")
def kibana_rules(check):
    sent = {"name": "zzz-audit-rule", "description": "audit", "risk_score": 42,
            "severity": "low", "type": "query", "query": "*:*", "index": ["logs-*"],
            "from": "now-6m", "interval": "5m", "enabled": False,
            "rule_id": "zzz-audit-rule-id", "tags": ["zzz-audit"]}
    created = check.request("POST", "/kibana/api/detection_engine/rules", json=sent)
    if not isinstance(created, dict) or "id" not in created:
        return
    check.echoes("POST /detection_engine/rules",
                 {k: sent[k] for k in ("name", "description", "risk_score", "severity",
                                       "query", "tags", "enabled", "rule_id")}, created)
    rule = created["id"]
    check.carries("GET /detection_engine/rules?id=",
                  check.get("/kibana/api/detection_engine/rules", params={"id": rule}),
                  "name", "zzz-audit-rule")
    check.listed("GET /rules/_find",
                 find(check.get("/kibana/api/detection_engine/rules/_find",
                                params={"per_page": "100"}), "data"), "id", rule)
    check.request("PUT", "/kibana/api/detection_engine/rules",
                  json={**sent, "id": rule, "name": "zzz-audit-rule-renamed"})
    check.carries("GET /rules?id= after PUT",
                  check.get("/kibana/api/detection_engine/rules", params={"id": rule}),
                  "name", "zzz-audit-rule-renamed")
    check.request("DELETE", "/kibana/api/detection_engine/rules", params={"id": rule})
    check.get("/kibana/api/detection_engine/rules", params={"id": rule}, expect=(404,))
    check.listed("GET /rules/_find after DELETE",
                 find(check.get("/kibana/api/detection_engine/rules/_find",
                                params={"per_page": "100"}), "data"),
                 "id", rule, present=False)


@cycle("kibana", "exception-lists")
def kibana_exception_lists(check):
    sent = {"list_id": "zzz-audit-list", "name": "zzz-audit", "description": "audit",
            "type": "detection", "namespace_type": "single", "tags": ["zzz-audit"]}
    created = check.request("POST", "/kibana/api/exception_lists", json=sent)
    if not isinstance(created, dict) or "id" not in created:
        return
    check.echoes("POST /exception_lists",
                 {k: sent[k] for k in ("list_id", "name", "description", "type", "tags")},
                 created)
    check.carries("GET /exception_lists?list_id=",
                  check.get("/kibana/api/exception_lists",
                            params={"list_id": "zzz-audit-list"}), "name", "zzz-audit")
    item = {"list_id": "zzz-audit-list", "item_id": "zzz-audit-item", "name": "zzz-audit-item",
            "description": "audit", "type": "simple", "namespace_type": "single",
            "entries": [{"field": "host.name", "operator": "included", "type": "match",
                         "value": "zzz-audit-host"}]}
    made = check.request("POST", "/kibana/api/exception_lists/items", json=item)
    if isinstance(made, dict):
        check.echoes("POST /exception_lists/items",
                     {k: item[k] for k in ("item_id", "name", "description", "entries")},
                     made)
        check.listed("GET /exception_lists/items/_find",
                     find(check.get("/kibana/api/exception_lists/items/_find",
                                    params={"list_id": "zzz-audit-list"}), "data"),
                     "item_id", "zzz-audit-item")
        check.request("DELETE", "/kibana/api/exception_lists/items",
                      params={"item_id": "zzz-audit-item"}, expect=(200, 204))
    check.request("DELETE", "/kibana/api/exception_lists",
                  params={"list_id": "zzz-audit-list"}, expect=(200, 204))
    check.get("/kibana/api/exception_lists", params={"list_id": "zzz-audit-list"},
              expect=(404,))


def main():
    wanted = sys.argv[1:]
    total = findings = 0
    for mount, name, function in CYCLES:
        if wanted and mount not in wanted:
            continue
        total += 1
        check = Check(mount, name)
        function(check)
        if check.findings:
            findings += len(check.findings)
            print(f"\n── {mount}/{name} ({len(check.findings)})")
            for where, what in check.findings:
                print(f"  {where}\n      {what}")
    print(f"\n=== ROUND TRIP === {total} cycle(s) written and read back")
    print(f"  {findings} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
