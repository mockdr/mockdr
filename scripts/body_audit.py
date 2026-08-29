# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Ask every write route whether it reads the body it declares.

A route that takes a body and checks nothing in it is the quietest defect a
mock can have. `/api/exception_lists/items` accepted an empty body and
created an exception with no entries — an exception that matches nothing, so
a rule carrying it behaves as though it were not there, and the client had
just been told it was created. Kibana refuses that body by naming every
member it wanted. Nothing in the mock's own tests could see the difference,
because both answers were a 200 with an id in it.

The rule this checks is one no vendor documentation is needed for: **a route
that declares a body must read it.** Each such route is sent four bodies
that cannot be what it meant:

* `{}` — nothing at all;
* `{"zzz_undeclared_member": 1}` — one member, and not one it declares.

Both are objects on purpose. A list or a string is refused by the framework
before the handler sees it, so probing with one measures FastAPI rather than
the route: every route "passes" and the audit reports nothing.

A route that answers 2xx to both read nothing of what it was sent. One that
refuses either is reading something, and how *well* it reads is what the
conformance harness measures against the real product.

Some routes are right to answer anything, and those are listed in the script
with the reason: most Cortex routes require nothing, and for Defender and
Graph the references this repo holds carry reply shapes only, so nothing can
be enforced without inventing it. Exit status is 1 for a route that is
neither reading its body nor on that list, so this gates a pipeline.

Routes with no declared body are skipped: an action route that ignores a
body is imitating a product that ignores it too. So is mockdr's own `_dev`
surface, which imitates nothing. So are the OAuth token
routes, which take a form rather than a document, `_bulk`-style routes whose
body is NDJSON text rather than JSON, and the ones whose body *is* the
client's own document — indexing `{}` into Elasticsearch answers 201 there,
and so does indexing anything else.

    backend/.venv/bin/python scripts/body_audit.py [mount ...]

Exit status 1 when anything is flagged.
"""

import base64
import logging
import re
import sys
import uuid
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
    token = (
        response.json().get("access_token")
        if response.headers.get("content-type", "").startswith("application/json")
        else None
    )
    return {"Authorization": f"Bearer {token}"} if token else None


AUTH = {
    "web": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
    "cs": oauth("/cs/oauth2/token", "cs-mock-admin-client", "cs-mock-admin-secret"),
    "mde": oauth("/mde/oauth2/v2.0/token", "mde-mock-admin-client",
                 "mde-mock-admin-secret",
                 {"scope": "https://api.securitycenter.microsoft.com/.default"}),
    "graph": oauth("/graph/oauth2/v2.0/token", "graph-mock-admin-client",
                   "graph-mock-admin-secret",
                   {"scope": "https://graph.microsoft.com/.default"}),
    "sentinel": oauth("/sentinel/oauth2/v2.0/token", "sentinel-mock-client-id",
                      "sentinel-mock-client-secret",
                      {"scope": "https://management.azure.com/.default"}),
    "xdr": {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
    "splunk": {"Authorization": "Basic " + base64.b64encode(
        b"admin:mockdr-admin").decode()},
    "elastic": {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()},
    "kibana": {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
        "kbn-xsrf": "true",
    },
}

#: Bodies that cannot be what any route meant. A route answering 2xx to all
#: four is not reading the one it declares.
_NONSENSE = (
    ("empty", {}),
    ("one undeclared member", {"zzz_undeclared_member": 1}),
)

#: mockdr's own control surface, which is not imitating anything — and must
#: not be poked by a sweep: posting to `_dev/scenario` reseeds the world,
#: which invalidated the tokens every later mount was being probed with and
#: turned three platforms' worth of routes into unexplained 401s.
_OWN_SURFACE = re.compile(r"/_dev/")

#: Paths whose body is not a JSON document at all, so a JSON probe says
#: nothing about them: NDJSON bulk streams, form posts, and raw event text.
_NOT_JSON = re.compile(
    r"/_bulk$|/_msearch$|/_mget$|/oauth2?/|/token$|/services/receivers/|"
    r"/collector(/|$)|/search/jobs/[^/]+/(events|results)$",
)

#: Routes whose body *is* the client's own document, so an object with any
#: member in it — or none — is exactly what they are for. Measured: indexing
#: `{}` into Elasticsearch answers 201, and so does indexing anything else.
_ANY_DOCUMENT = re.compile(r"/_doc(/|$)|/_create/|/_source$")

#: Routes that answer any body, and stay that way because no reference this
#: repo holds says otherwise. Each one was looked up, not waved through:
#: refusing a body a vendor may well accept is the same class of defect in
#: the other direction. When a reference for one of these arrives, the route
#: leaves this list rather than the list growing to meet it.
_NOTHING_SAYS_OTHERWISE = {
    # The Cortex reference states a requirement for 68 of its routes and
    # none for these — `xql/get_quota` gives `{"request_data": null}` as its
    # own example.
    "POST /xdr/public_api/v1/alerts_exclusion/",
    "POST /xdr/public_api/v1/device_control/get_violations/",
    "POST /xdr/public_api/v1/distributions/get_versions/",
    "POST /xdr/public_api/v1/rbac/get_roles/",
    "POST /xdr/public_api/v1/rbac/get_users/",
    "POST /xdr/public_api/v1/system/get_tenant_info/",
    "POST /xdr/public_api/v1/tags/agents/assign/",
    "POST /xdr/public_api/v1/tags/agents/remove/",
    "POST /xdr/public_api/v1/xql/get_quota",
    # Not in the SentinelOne 2.1 swagger at all — `param_drift.py` counts
    # them among the routes the vendor does not publish, which is the
    # question to settle before this one.
    "POST /web/api/v2.1/threat-intelligence/iocs/bulk",
    "POST /web/api/v2.1/threats/mark-as-resolved",
    "POST /web/api/v2.1/threats/mark-as-threat",
    # Documented, with `data` optional and nothing required inside it.
    "POST /web/api/v2.1/threats/engines/disable",
    # gofalcon carries no request schema for this one, and marks nothing
    # required on the other.
    "POST /cs/user-management/entities/users/GET/v1",
    "PATCH /cs/quarantine/entities/quarantined-files/v1",
    # `mde_docs_reduced.json` and the Graph CSDL keep reply shapes only, so
    # neither says what these bodies must carry.
    "POST /mde/api/alerts/batchUpdate",
    "POST /mde/api/alerts/createAlertByReference",
    "POST /mde/api/indicators/BatchDelete",
    "POST /graph/v1.0/informationProtection/threatAssessmentRequests",
    "POST /graph/v1.0/security/runHuntingQuery",
}

#: A route can only be judged on a body if it gets that far, so the path
#: parameters have to resolve to something the mock holds.
_IDS = {"web": "1", "cs": "1", "mde": "1", "graph": "1"}


def fill(path, mount):
    def sub(match):
        name = match.group(1).lower()
        if "uuid" in name or name.endswith("_id") or name == "id" or "sid" in name:
            return _IDS.get(mount, str(uuid.uuid4()))
        if "index" in name or "name" in name or "collection" in name:
            return "zzz-conformance"
        return "x"
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", sub, path)


def write_routes(wanted):
    """Every route that declares a body, with the verb it takes it on.

    The schema is the authority on what a route declares: the mounts are
    sub-applications, so walking `app.routes` finds their paths without the
    prefix a client would send.
    """
    for path, operations in app.openapi()["paths"].items():
        mount = path.split("/")[1]
        if (wanted and mount not in wanted) or AUTH.get(mount) is None:
            continue
        if (_NOT_JSON.search(path) or _ANY_DOCUMENT.search(path)
                or _OWN_SURFACE.search(path)):
            continue
        for verb in ("post", "put", "patch"):
            operation = operations.get(verb)
            if operation and operation.get("requestBody"):
                yield mount, verb.upper(), path


def main():
    wanted = sys.argv[1:]
    flags, checked = [], 0
    for mount, verb, path in write_routes(wanted):
        headers = AUTH[mount]
        url = fill(path, mount)
        answers = []
        for label, body in _NONSENSE:
            response = client.request(verb, url, headers=headers, json=body)
            answers.append((label, response.status_code))
        # A route the request never reached — an unresolved path parameter,
        # a 404, an auth refusal — says nothing about how it reads a body.
        if all(status >= 400 for _, status in answers):
            continue
        checked += 1
        if all(200 <= status < 300 for _, status in answers):
            flags.append((mount, verb, path))

    known = [f for f in flags if f"{f[1]} {f[2]}" in _NOTHING_SAYS_OTHERWISE]
    flags = [f for f in flags if f"{f[1]} {f[2]}" not in _NOTHING_SAYS_OTHERWISE]

    print(f"=== BODY CONTRACT === {checked} write route(s) exercised")
    by_mount = {}
    for mount, verb, path in flags:
        by_mount.setdefault(mount, []).append((verb, path))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for verb, path in sorted(by_mount[mount]):
            print(f"  {verb:<6} {path}")
    print(f"\n  {len(flags)} route(s) that read nothing of the body they declare"
          f", {len(known)} left that way because no reference says otherwise")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
