# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Check the HTTP level itself, route by route, against what each product does.

Everything else here reads bodies. This reads what sits above them, which a
client reads too and a mock is unusually likely to answer uniformly:

* **the content type**, whose charset three products spell three ways —
  Kibana lower-case, splunkd upper-case, Elasticsearch not at all;
* **a verb the route does not take**, which is a 405 with `Allow` on
  Elasticsearch, a 404 with none on Kibana, and — on splunkd — either,
  depending on which of the three services under that one mount owns the
  path: its EAI collections answer 400 and have no 405 at all, while the
  search endpoints and the KV store answer a proper 405;
* **`HEAD`**, which Elasticsearch serves on its existence endpoints alone and
  Kibana and splunkd serve wherever they serve `GET`;
* **the `WWW-Authenticate` challenge** on a 401, which Elasticsearch sends as
  two headers, splunkd as one, and Kibana not at all.

Each rule is measured — Elasticsearch 8.15, Kibana 8.15, Splunk 10.4.2 — and
the sweep is over *every* route of those mounts, because one hand-probe per
mount cannot see a route that behaves unlike its neighbours.

The six mounts with no runnable product are counted and reported as
unjudged rather than guessed at. Exit status 1 when anything is flagged.

    backend/.venv/bin/python scripts/http_contract_audit.py [mount ...]
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


def _basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(
        f"{user}:{password}".encode()).decode()}


AUTH = {
    "splunk": _basic("admin", "mockdr-admin"),
    "elastic": _basic("elastic", "mock-elastic-password"),
    "kibana": {**_basic("elastic", "mock-elastic-password"), "kbn-xsrf": "true"},
}

#: What each product writes for a JSON body, measured.
CONTENT_TYPE = {
    "splunk": "application/json; charset=UTF-8",
    "elastic": "application/json",
    "kibana": "application/json; charset=utf-8",
}

#: What each answers to a verb the route does not take: the status, and
#: whether an `Allow` header comes with it.
WRONG_METHOD = {
    "splunk": (400, False),
    "elastic": (405, True),
    "kibana": (404, False),
}

#: The splunkd paths that answer a proper 405 instead of the EAI 400 — the
#: search service and the KV store, which are not the config handlers.
_SPLUNK_405 = re.compile(r"/splunk/services/search/|/storage/collections/data/[^/]+/batch_")

#: Where Elasticsearch serves HEAD. Everywhere else under `/elastic` is a
#: 405; Kibana and splunkd serve it wherever they serve GET.
_ES_HEAD = re.compile(
    r"^/elastic/?$|^/elastic/[^_/][^/]*/?$"
    r"|^/elastic/[^/]+/_doc/[^/]+/?$"
    r"|^/elastic/_alias/[^/]+/?$|^/elastic/[^/]+/_alias/[^/]+/?$",
)

#: Splunk's HEC is a different service under the same mount, with a 405 of
#: its own; the search routes take a POST body that a HEAD cannot carry.
_SKIP = re.compile(r"/splunk/services/collector|/oauth2/|/token$|/console/proxy")

#: Query parameters a route needs before it will look at anything.
PARAMS = {"output_mode": "json", "api-version": "2024-03-01"}
_MISSING = "zzz-no-such-id-00000000"


def fill(path):
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", _MISSING, path)


def judge(mount, path, methods):
    """Every way this one route departs from its product's HTTP contract."""
    found = []
    headers = AUTH[mount]
    url = fill(path)

    if "get" in methods:
        answer = client.get(url, headers=headers, params=PARAMS)
        actual = answer.headers.get("content-type", "")
        if actual.startswith("application/json") and actual != CONTENT_TYPE[mount]:
            found.append(("content type", f"{actual!r}, not {CONTENT_TYPE[mount]!r}"))

        # HEAD, where the product's rule says it is served.
        served = mount != "elastic" or bool(_ES_HEAD.match(url))
        head = client.request("HEAD", url, headers=headers, params=PARAMS)
        if served and head.status_code == 405:
            found.append(("HEAD", "answered 405 where the product serves it"))
        if not served and head.status_code != 405:
            found.append(("HEAD", f"answered {head.status_code} where the product "
                                  f"answers 405"))

    unused = {"delete", "patch", "put"} - methods
    if unused:
        want_status, want_allow = WRONG_METHOD[mount]
        if mount == "splunk" and _SPLUNK_405.search(path):
            want_status, want_allow = 405, True
        answer = client.request(sorted(unused)[0].upper(), url,
                                headers=headers, params=PARAMS)
        if answer.status_code != want_status:
            found.append((f"{sorted(unused)[0].upper()} it does not take",
                          f"answered {answer.status_code}, not {want_status}"))
        has_allow = "allow" in {k.lower() for k in answer.headers}
        if has_allow is not want_allow:
            found.append(("Allow header",
                          f"{'present' if has_allow else 'absent'} where the product "
                          f"sends {'one' if want_allow else 'none'}"))
    return found


def main():
    wanted = sys.argv[1:]
    flags, checked, unjudged = [], 0, 0
    for path, operations in app.openapi()["paths"].items():
        mount = path.split("/")[1]
        methods = {m for m in operations if m in ("get", "post", "put", "patch", "delete")}
        if not methods:
            continue
        if mount not in AUTH:
            unjudged += 1
            continue
        if _SKIP.search(path) or (wanted and mount not in wanted):
            continue
        checked += 1
        flags += [(mount, path, *f) for f in judge(mount, path, methods)]

    print(f"=== HTTP CONTRACT === {checked} route(s) checked against a measured "
          f"product, {unjudged} on mounts with none")
    by_mount = {}
    for mount, path, what, why in flags:
        by_mount.setdefault(mount, []).append((what, path, why))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for what, path, why in sorted(by_mount[mount]):
            print(f"  {what:<26} {path}\n      {why}")
    print(f"\n  {len(flags)} departure(s) from the product's HTTP contract")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
