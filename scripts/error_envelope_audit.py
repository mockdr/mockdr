# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Check that every refusal is shaped the way its vendor shapes refusals.

The hostile probe asks whether a route *crashes*. This asks the quieter
question beside it: when a route refuses, does it refuse in the vendor's own
envelope? A client parses errors with one parser — `errors[0].message` for
Falcon, `error.code` for Graph, `reply.err_msg` for Cortex, `messages[0].text`
for splunkd — and a 404 that answers FastAPI's `{"detail": …}` is a 404 the
client cannot read. It looks like a working refusal in a browser and breaks
every integration that inspects it.

*Every* route is swept, not a sample: each is sent the refusals a client
actually meets — an id that does not exist, a method the route does not
take, no credential at all, a body that is not an object, and a body that is
not JSON — and each answer is checked against the shape that vendor uses.
`utils/vendor_errors.py` already maps a path to its vendor for
framework-level failures; this checks that the *handlers* agree with it.

Exit status 1 when anything is flagged.

    backend/.venv/bin/python scripts/error_envelope_audit.py [mount ...]
"""

import base64
import json
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
    # Falcon answers 201 for a token, the Microsoft mounts 200.
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


def _has(body, *paths: str):
    """Whether the body carries any of these dotted paths."""
    for path in paths:
        cursor = body
        for step in path.split("."):
            if step == "[]":
                if not isinstance(cursor, list) or not cursor:
                    cursor = None
                    break
                cursor = cursor[0]
            elif isinstance(cursor, dict) and step in cursor:
                cursor = cursor[step]
            else:
                cursor = None
                break
        if cursor is not None:
            return True
    return False


#: What a refusal from each mount must carry. A body that satisfies none of a
#: vendor's shapes is not that vendor's refusal, whatever its status says.
SHAPES = {
    "web": ("errors.[].detail", "errors.[].title", "errors"),
    "cs": ("errors.[].message", "errors.[].code"),
    "mde": ("error.code", "error.message"),
    "graph": ("error.code", "error.message"),
    "sentinel": ("error.code", "error.message"),
    "xdr": ("reply.err_msg", "reply.err_code"),
    # HEC is a different service from splunkd and refuses in its own shape —
    # a flat `text` and a numeric `code` — which is why `vendor_errors.py`
    # maps `/splunk/services/collector` to a vendor of its own.
    "splunk": ("messages.[].text", "messages.[].type", "text", "code"),
    # Elasticsearch's 405 carries a bare string where every other status
    # carries the nested object; both are the product's (measured on 8.15,
    # pinned in `test_unknown_route_conformance.py`).
    "elastic": ("error.type", "error.reason", "error.root_cause", "status"),
    "kibana": ("message", "error", "statusCode"),
}

#: Splunk answers Atom XML unless asked for JSON, and `_cat` is a text API:
#: a text body there is the contract, not a leak.
_TEXT_IS_THE_CONTRACT = re.compile(r"^/splunk(?!.*output_mode=json)|^/elastic/_cat/")

#: A route per mount used for the id-shaped probes, kept because a path
#: parameter has to resolve to something the mount recognises.
PROBES = {
    "web": ("/web/api/v2.1/agents/{id}", "/web/api/v2.1/agents"),
    "cs": ("/cs/devices/entities/devices/v2?ids={id}", "/cs/devices/queries/devices/v1"),
    "mde": ("/mde/api/machines/{id}", "/mde/api/machines"),
    "graph": ("/graph/v1.0/security/alerts_v2/{id}", "/graph/v1.0/security/alerts_v2"),
    "sentinel": (
        "/sentinel/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups"
        "/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-ws"
        "/providers/Microsoft.SecurityInsights/incidents/{id}?api-version=2024-03-01",
        "/sentinel/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups"
        "/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-ws"
        "/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01",
    ),
    "xdr": (None, "/xdr/public_api/v1/incidents/get_incidents/"),
    "splunk": ("/splunk/services/data/indexes/{id}?output_mode=json",
               "/splunk/services/data/indexes?output_mode=json"),
    "elastic": ("/elastic/{id}/_doc/1", "/elastic/_cluster/health"),
    "kibana": ("/kibana/api/cases/{id}", "/kibana/api/cases/_find"),
}

_MISSING = "zzz-no-such-id-00000000"


def judge(mount, label, response):
    """Whether one refusal carries its vendor's envelope."""
    if 200 <= response.status_code < 300:
        return None                      # not a refusal; nothing to judge here
    content_type = response.headers.get("content-type", "")
    if not content_type.startswith("application/json"):
        if _TEXT_IS_THE_CONTRACT.match(str(response.request.url.path)):
            return None
        return (label, response.status_code,
                f"answered {content_type or 'no content type'}, not JSON")
    try:
        body = response.json()
    except ValueError:
        return (label, response.status_code, "the body is not JSON after all")
    if _has(body, "detail"):
        # FastAPI's own shape, which no vendor here uses. A vendor envelope
        # nested *under* detail is the same leak: the client sees `detail`.
        return (label, response.status_code,
                f"FastAPI's {{'detail': …}} leaked: {json.dumps(body)[:110]}")
    if _has(body, "result") and _has(body, "_index"):
        # Not every refusal is an *error*: Elasticsearch answers a delete that
        # found nothing with the document envelope and a 404, and a client
        # reads `result` rather than an error type. Measured on 8.15.
        return None
    if not _has(body, *SHAPES[mount]):
        return (label, response.status_code,
                f"none of {SHAPES[mount]}: {json.dumps(body)[:110]}")
    return None


def fill(path, mount):
    """A path with its parameters resolved to something that does not exist."""
    def sub(match):
        name = match.group(1).lower()
        if "index" in name or "alias" in name:
            return _MISSING
        if "collection" in name or "name" in name:
            return _MISSING
        return _MISSING
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", sub, path)


#: Routes whose whole purpose is to answer whatever they are given, so a
#: "refusal" from them is the upstream's and not this mount's.
_PASSTHROUGH = re.compile(r"/console/proxy|/oauth2/|/token$|/_bulk|/_msearch")


def sweep():
    """Every route, with the refusals a client actually meets."""
    for path, operations in app.openapi()["paths"].items():
        mount = path.split("/")[1]
        if mount not in AUTH or _PASSTHROUGH.search(path):
            continue
        headers = AUTH[mount]
        url = fill(path, mount)
        methods = {m for m in operations if m in ("get", "post", "put", "patch", "delete")}
        if not methods:
            continue
        # Query parameters some mounts need before they will look at anything.
        params = {"api-version": "2024-03-01", "output_mode": "json", "ids": _MISSING,
                  "id": _MISSING, "list_id": _MISSING, "item_id": _MISSING}

        for method in sorted(methods):
            yield mount, f"{method.upper()} {path} — an id that is not there", client.request(
                method.upper(), url, headers=headers, params=params,
                json={} if method in ("post", "put", "patch") else None)

        first = sorted(methods)[0]
        yield mount, f"{first.upper()} {path} — no credential", client.request(
            first.upper(), url, params=params,
            json={} if first in ("post", "put", "patch") else None)

        unused = {"delete", "patch", "put"} - methods
        if unused:
            method = sorted(unused)[0]
            yield mount, f"{method.upper()} {path} — a method it does not take", client.request(
                method.upper(), url, headers=headers, params=params)

        if methods & {"post", "put", "patch"}:
            method = sorted(methods & {"post", "put", "patch"})[0]
            yield mount, f"{method.upper()} {path} — a body that is not an object", (
                client.request(method.upper(), url, headers=headers, params=params,
                               json=["not", "an", "object"]))
            yield mount, f"{method.upper()} {path} — a body that is not JSON", (
                client.request(method.upper(), url, params=params,
                               headers={**headers, "Content-Type": "application/json"},
                               content=b"{not json"))


def main():
    wanted = sys.argv[1:]
    flags, checked = [], 0
    for mount, label, response in sweep():
        if wanted and mount not in wanted:
            continue
        checked += 1
        found = judge(mount, label, response)
        if found:
            flags.append((mount, *found))

    print(f"=== ERROR ENVELOPES === {checked} refusal(s) read")
    by_mount = {}
    for mount, label, status, what in flags:
        by_mount.setdefault(mount, []).append((label, status, what))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for label, status, what in sorted(by_mount[mount]):
            print(f"  {status}  {label}\n      {what}")
    print(f"\n  {len(flags)} refusal(s) a client of that vendor could not parse")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
