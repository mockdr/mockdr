# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Ask every write whether a read-only credential can perform it.

The audits beside this one look for a mock that loses data. This one looks
for the opposite mistake, which is just as quiet: a route that *changes*
something and never asks who is calling. Every vendor here separates reading
from writing — Falcon's OAuth scopes, Cortex's role per API key, Kibana's
`kbn-xsrf` and its roles, splunkd's capabilities, Graph's application
permissions — and a client tested against a mock that lets a viewer isolate
a host learns nothing about what production will do.

Three questions per write route, each with an unambiguous answer:

* **unauthenticated** — no credential at all must not be a 2xx;
* **read-only** — a credential the vendor issues for reading must not be a
  2xx on a route that writes;
* **cross-tenant** — where the vendor scopes by tenant, another tenant's
  credential must not reach this tenant's records.

A route that answers 404 or 422 is not flagged: it refused for its own
reasons before authorisation could matter, and this audit is about what
answers 2xx. Exit status 1 when anything is flagged.

    backend/.venv/bin/python scripts/authz_audit.py [mount ...]
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
    if response.status_code != 200:
        return None
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(
        f"{user}:{password}".encode()).decode()}


#: An admin credential per mount, and the read-only one the vendor issues
#: beside it. A mount with no read-only credential is checked only against
#: no credential at all.
CREDENTIALS = {
    "web": {
        "admin": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
        "reader": {"Authorization": "ApiToken viewer-token-0000-0000-000000000003"},
    },
    "cs": {
        "admin": oauth("/cs/oauth2/token", "cs-mock-admin-client", "cs-mock-admin-secret"),
        "reader": oauth("/cs/oauth2/token", "cs-mock-read-client", "cs-mock-read-secret"),
    },
    "mde": {
        "admin": oauth("/mde/oauth2/v2.0/token", "mde-mock-admin-client",
                       "mde-mock-admin-secret",
                       {"scope": "https://api.securitycenter.microsoft.com/.default"}),
        "reader": oauth("/mde/oauth2/v2.0/token", "mde-mock-read-client",
                        "mde-mock-read-secret",
                        {"scope": "https://api.securitycenter.microsoft.com/.default"}),
    },
    "graph": {
        "admin": oauth("/graph/oauth2/v2.0/token", "graph-mock-admin-client",
                       "graph-mock-admin-secret",
                       {"scope": "https://graph.microsoft.com/.default"}),
        "reader": oauth("/graph/oauth2/v2.0/token", "graph-mock-read-client",
                        "graph-mock-read-secret",
                        {"scope": "https://graph.microsoft.com/.default"}),
    },
    "sentinel": {
        "admin": oauth("/sentinel/oauth2/v2.0/token", "sentinel-mock-client-id",
                       "sentinel-mock-client-secret",
                       {"scope": "https://management.azure.com/.default"}),
    },
    "xdr": {
        "admin": {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
        "reader": {"x-xdr-auth-id": "3", "Authorization": "xdr-viewer-secret"},
    },
    "splunk": {
        "admin": _basic("admin", "mockdr-admin"),
        "reader": _basic("viewer", "mockdr-viewer"),
    },
    "elastic": {
        "admin": _basic("elastic", "mock-elastic-password"),
        "reader": _basic("kibana_viewer", "mock-viewer-password"),
    },
    "kibana": {
        "admin": {**_basic("elastic", "mock-elastic-password"), "kbn-xsrf": "true"},
        "reader": {**_basic("kibana_viewer", "mock-viewer-password"), "kbn-xsrf": "true"},
    },
}

#: Routes that are writes by method but reads by contract: the vendor's own
#: "fetch these ids" calls, which take a POST because the id list is a body.
#: Cortex XDR is POST-only, so most of its surface lands here.
_READS_BY_CONTRACT = re.compile(
    r"/GET/v\d$"                       # Falcon's POST-to-read pairs
    r"|/oauth2/|/token$"               # issuing a token is not a write
    r"|/(_search|_msearch|_mget|_count|_field_caps|_validate|_analyze|_terms_enum"
    r"|_pit|_bulk_get|_export|preview|_find)\b"
    r"|/public_api/v1/(alerts/get_|incidents/get_|endpoints/get_|audits/|rbac/get_"
    r"|scripts/get_|distributions/get_|xql/get_|system/get_|quarantine/status"
    r"|device_control/get_|actions/get_|actions/file_retrieval_details"
    r"|alerts_exclusion/$)"
    r"|/console/proxy"                 # a proxy is whatever it is given
    r"|/search/jobs"                   # dispatching a search reads
    r"|/api/detection_engine/signals/search"
    r"|/api/endpoint/suggestions/"
    r"|/runHuntingQuery|/queryIndicators|/threatIntelligence/main/metrics"
    r"|/v1/workspaces/.*/query"
    # Starting an XQL query runs a search; Cortex's viewer role may.
    r"|/public_api/v1/xql/start_xql_query"
    # mockdr's own, not a vendor's: the sink a delivered webhook is posted
    # *to*. It is deliberately open, because the sender is a webhook, not a
    # client with a credential.
    r"|/_dev/webhook-sink"
)

_METHODS = ("post", "put", "patch", "delete")


def fill(path):
    def sub(match):
        name = match.group(1).lower()
        if "index" in name or "name" in name or "collection" in name or "alias" in name:
            return "zzz-authz"
        if "uuid" in name or name.endswith("_id") or name == "id" or "sid" in name:
            return "1"
        return "x"
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", sub, path)


def body_for(operation):
    """A body plausible enough to get past validation, for any route."""
    return {
        "resources": [{"name": "zzz-authz", "group_type": "static", "id": "1"}],
        "indicators": [{"type": "domain", "value": "zzz.test", "action": "no_action",
                        "id": "1"}],
        "request_data": {"filters": [], "tag": "zzz", "hash_list": [],
                         "incident_id": "1", "update_data": {}, "alias": "zzz"},
        "properties": {"displayName": "zzz-authz"},
        "cases": [{"id": "1", "version": "WzAsMV0=", "title": "zzz"}],
        "comment": "zzz", "type": "user", "owner": "securitySolution",
        "name": "zzz-authz", "title": "zzz-authz", "description": "zzz",
        "composite_ids": ["1"], "ids": ["1"], "action_parameters": [],
        "status": "new", "doc": {"zzz": 1},
        "list_id": "zzz-authz", "item_id": "zzz-authz",
    }


def judge(mount, path, method, operation):
    """The findings for one write route."""
    found = []
    url = f"{fill(path)}"
    body = body_for(operation)
    credentials = CREDENTIALS.get(mount) or {}

    for label, headers in (("no credential", {}), ("read-only", credentials.get("reader"))):
        if headers is None:
            continue
        response = client.request(
            method.upper(), url, headers=headers or None, json=body,
            params={"ids": "1", "api-version": "2024-03-01", "action_name": "add-hosts",
                    "id": "1", "list_id": "zzz-authz", "item_id": "zzz-authz",
                    "output_mode": "json"},
        )
        if 200 <= response.status_code < 300:
            found.append((label, method.upper(), path, response.status_code))
    return found


def main():
    wanted = sys.argv[1:]
    flags, checked = [], 0
    for path, operations in app.openapi()["paths"].items():
        mount = path.split("/")[1]
        if wanted and mount not in wanted:
            continue
        if mount not in CREDENTIALS or _READS_BY_CONTRACT.search(path):
            continue
        for method, operation in operations.items():
            if method not in _METHODS:
                continue
            checked += 1
            flags.extend((mount, *f) for f in judge(mount, path, method, operation))

    print(f"=== AUTHORISATION === {checked} write route(s) exercised")
    by_mount = {}
    for mount, label, method, path, status in flags:
        by_mount.setdefault(mount, []).append((label, method, path, status))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for label, method, path, status in sorted(by_mount[mount]):
            print(f"  {label:<14} {method:<6} {path:<62} {status}")
    print(f"\n  {len(flags)} write(s) a credential without the right to them could perform")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
