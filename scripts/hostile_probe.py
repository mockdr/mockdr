# ruff: noqa: ANN, D103, S311, E402
# A release tool, not library code: the random is for coverage, every function
# is local to this file, and sys.path is set before the project imports on purpose.
"""Send hostile bodies and parameters to every route; flag anything that crashes.

The single highest-yield bug finder this project has: twelve plain-text 500s
before 2.0.1, thirty-one before 2.0.5. Run it before every release:

    backend/.venv/bin/python scripts/hostile_probe.py

It authenticates against every mount with the seeded credentials, fills path
parameters with plausible values, and sends each route null, arrays, strings,
deep nesting, a 300 KB string, negative and non-numeric query parameters.
A route is flagged for a 5xx, a plain-text or HTML body on a vendor mount,
or a traceback in the response. Exit status 1 when anything is flagged.
"""

import base64
import json
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

c = TestClient(app, raise_server_exceptions=False).__enter__()


def oauth(path, cid, sec, extra=None):
    r = c.post(
        path,
        data={
            "grant_type": "client_credentials",
            "client_id": cid,
            "client_secret": sec,
            **(extra or {}),
        },
    )
    t = (
        r.json().get("access_token")
        if r.headers.get("content-type", "").startswith("application/json")
        else None
    )
    return ({"Authorization": f"Bearer {t}"} if t else None), r.status_code


AUTH = {
    "web": ({"Authorization": "ApiToken admin-token-0000-0000-000000000001"}, 200),
    "cs": oauth("/cs/oauth2/token", "cs-mock-admin-client", "cs-mock-admin-secret"),
    "mde": oauth(
        "/mde/oauth2/v2.0/token",
        "mde-mock-admin-client",
        "mde-mock-admin-secret",
        {"scope": "https://api.securitycenter.microsoft.com/.default"},
    ),
    "graph": oauth(
        "/graph/oauth2/v2.0/token",
        "graph-mock-admin-client",
        "graph-mock-admin-secret",
        {"scope": "https://graph.microsoft.com/.default"},
    ),
    "sentinel": oauth(
        "/sentinel/oauth2/v2.0/token",
        "sentinel-mock-client-id",
        "sentinel-mock-client-secret",
        {"scope": "https://management.azure.com/.default"},
    ),
    "xdr": ({"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}, 200),
    "splunk": ({"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}, 200),
    "elastic": (
        {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()},
        200,
    ),
    "kibana": (
        {
            "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
            "kbn-xsrf": "true",
        },
        200,
    ),
}
print("auth:", {k: ("ok" if v[0] else f"FAILED({v[1]})") for k, v in AUTH.items()})

paths = app.openapi()["paths"]


def fill(path):
    def sub(m):
        n = m.group(1).lower()
        if "uuid" in n or n.endswith("_id") or n == "id" or "sid" in n:
            return str(uuid.uuid4())
        if "index" in n or "name" in n or "collection" in n:
            return "zzz-conformance"
        return "x"

    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", sub, path)


DEEP = json.loads('{"a":' * 300 + "1" + "}" * 300)
BODIES = [
    None,
    "null",
    "[]",
    '""',
    '"x"',
    "123",
    "{}",
    '{"a":null}',
    json.dumps(DEEP),
    json.dumps({"s": "x" * 300000}),
    '{"limit":-1,"count":-1,"size":-1,"page":0,"per_page":0}',
    '{"ids":null,"filter":null,"query":null,"event":null,"events":null}',
    "{not json",
    "\x00",
]
QUERIES = [
    "",
    "?limit=abc&count=-1&skip=99999999999999999999&page=0&per_page=0&pageSize=0&size=-1&from=-1",
    "?sortBy=;;&sortOrder=x&$filter=(((&$orderby=x%20desc%20x&$top=-1&$skip=abc&$select=&output_mode=<script>&offset=-1&search_after=x",
    "?q=" + "(" * 500 + "&query=" + "{" * 500 + "&filter=" + "'" * 500,
]

flags = []
n = 0
for path, methods in paths.items():
    if path.startswith("/web/api/v2.1/_dev") or "full_path" in path:
        continue
    mount = path.split("/")[1]
    hdr = AUTH.get(mount, (None,))[0] or {}
    url = fill(path)
    for method in methods:
        M = method.upper()
        for q in QUERIES:
            for body in BODIES if M in ("POST", "PUT", "PATCH", "DELETE") else [None]:
                n += 1
                try:
                    kw = {"headers": {**hdr, "Content-Type": "application/json"}}
                    if body is not None:
                        kw["content"] = (
                            body.encode("utf-8", "surrogatepass") if isinstance(body, str) else body
                        )
                    r = c.request(M, url + q, **kw)
                except Exception as e:
                    flags.append(
                        (
                            mount,
                            M,
                            url + q[:30],
                            "EXC",
                            f"{type(e).__name__}: {str(e)[:60]}",
                            repr(body)[:30],
                        )
                    )
                    continue
                ct = r.headers.get("content-type", "")
                txt = r.text[:200]
                bad = (
                    r.status_code >= 500
                    or "Traceback" in txt
                    or "Internal Server Error" in txt
                    or "RecursionError" in txt
                )
                if (
                    not bad
                    and mount != "splunk"
                    and r.status_code != 204
                    and not ct.startswith(
                        (
                            "application/json",
                            "application/x-ndjson",
                            "application/ndjson",
                            "text/csv",
                            "application/octet-stream",
                            "application/zip",
                            "text/event-stream",
                        )
                    )
                ):
                    bad = True
                if bad:
                    flags.append(
                        (
                            mount,
                            M,
                            url + q[:40],
                            r.status_code,
                            ct[:30] + " " + txt.replace("\n", " ")[:70],
                            repr(body)[:30],
                        )
                    )
print(f"=== HOSTILE RESULT === {n} requests over {len(paths)} paths")
seen = set()
for f in flags:
    key = (f[0], f[1], f[2].split("?")[0], f[3], f[4][:40])
    if key in seen:
        continue
    seen.add(key)
    print("  " + " | ".join(str(x) for x in f))
print(f"  {len(seen)} distinct flags, {len(flags)} total")
raise SystemExit(1 if seen else 0)
