# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Check the HTTP level itself, route by route, against what each product does.

Everything else here reads bodies. This reads what sits above them, which a
client reads too and a mock is unusually likely to answer uniformly:

* **the content type**, whose charset three products spell three ways —
  Kibana lower-case, splunkd upper-case, Elasticsearch not at all;
* **a verb the route does not take**, which is a 405 with `Allow` on
  Elasticsearch, a 404 with none on Kibana, and — on splunkd — decided by
  the verb before the path: `PATCH` is a bare 405 everywhere, `PUT` is the
  EAI `404 Requested invalid action 'PUT'.` on a config handler and a 405 on
  the search service, and only the verbs that reach a handler depend on
  where they land.  splunkd sends `Allow` on none of the first two;
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

#: The search service, and the KV store's batch endpoints, which answer a
#: proper 405 where the config handlers answer the EAI 400.
_SPLUNK_SEARCH = re.compile(r"/splunk/services/search/")
_SPLUNK_KVSTORE_BATCH = re.compile(r"/storage/collections/data/[^/]+/batch_")
_SPLUNK_TYPEAHEAD = re.compile(r"/splunk/services/search/typeahead")

#: Where Elasticsearch serves HEAD. Everywhere else under `/elastic` is a
#: 405; Kibana and splunkd serve it wherever they serve GET.
_ES_HEAD = re.compile(
    r"^/elastic/?$|^/elastic/[^_/][^/]*/?$"
    r"|^/elastic/[^/]+/_doc/[^/]+/?$"
    # `HEAD /{index}/_source/{id}` asks whether a document's source exists:
    # 200 when it does, 404 when it does not.  Measured on 8.15.
    r"|^/elastic/[^/]+/_source/[^/]+/?$"
    r"|^/elastic/_alias/[^/]+/?$|^/elastic/[^/]+/_alias/[^/]+/?$",
)

#: Splunk's HEC is a different service under the same mount, with a 405 of
#: its own; the search routes take a POST body that a HEAD cannot carry.
_SKIP = re.compile(r"/splunk/services/collector|/oauth2/|/token$|/console/proxy")

#: Query parameters a route needs before it will look at anything.
#: Per mount, because a parameter belonging to another product is not a
#: neutral addition: Elasticsearch refuses an unrecognised one with a 400,
#: so sending splunkd's `output_mode` to it measured the parameter check
#: rather than the question asked.
PARAMS = {
    "splunk": {"output_mode": "json"},
    "elastic": {},
    "kibana": {},
}
_MISSING = "zzz-no-such-id-00000000"


def fill(path):
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", _MISSING, path)


#: The two search endpoints that resolve the sid before they judge the verb;
#: with a name that does not exist, a verb they do not take is a 404 and not
#: a 405.  Everything else under a job judges the verb first.
#: An EAI handler's `{name}/{custom action}` paths, where a verb the action
#: does not allow is a 404 naming the handler.
_SPLUNK_CUSTOM_ACTION = re.compile(
    r"/splunk/services/(saved/searches|data/indexes)/\{[^}]+\}/[^/]+/?$")

_SPLUNK_SID_FIRST = re.compile(
    r"/splunk/services/search/(v2/)?jobs/\{[^}]+\}(/control)?/?$")


def _splunk_expectation(verb, path):
    """What splunkd answers to *verb* on *path*, measured on 10.4.2.

    The rule is the verb's before it is the path's, which is what the earlier
    per-path table got wrong: `PATCH` is a bare 405 on every handler in every
    service, and `PUT` is the EAI 404 `Requested invalid action 'PUT'.` on the
    config handlers and a 405 on the search service.  Only the verbs that
    reach a handler — `DELETE` among them — depend on where they land, and
    splunkd sends `Allow` on none of the first three.
    """
    if verb == "PATCH":
        return 405, False
    search = bool(_SPLUNK_SEARCH.search(path))
    if verb == "PUT":
        return (405, False) if search else (404, False)
    if _SPLUNK_TYPEAHEAD.search(path):
        return 405, False
    if _SPLUNK_SID_FIRST.search(path):
        return 404, False          # `Unknown sid.`, before the verb is judged
    if verb == "DELETE" and _SPLUNK_CUSTOM_ACTION.search(path):
        # An EAI handler maps the verb to an eai action and then looks for the
        # trailing segment among that action's custom actions: 404 `Invalid
        # custom action for this internal handler (...)`, never the 400 about
        # a target name the path plainly carries.
        return 404, False
    if search or _SPLUNK_KVSTORE_BATCH.search(path):
        return 405, True
    return 400, False


def judge(mount, path, methods):
    """Every way this one route departs from its product's HTTP contract."""
    found = []
    headers = AUTH[mount]
    url = fill(path)

    if "get" in methods:
        answer = client.get(url, headers=headers, params=PARAMS[mount])
        actual = answer.headers.get("content-type", "")
        if actual.startswith("application/json") and actual != CONTENT_TYPE[mount]:
            found.append(("content type", f"{actual!r}, not {CONTENT_TYPE[mount]!r}"))

        # HEAD, where the product's rule says it is served.
        served = mount != "elastic" or bool(_ES_HEAD.match(url))
        head = client.request("HEAD", url, headers=headers, params=PARAMS[mount])
        if served and head.status_code == 405:
            found.append(("HEAD", "answered 405 where the product serves it"))
        if not served and head.status_code != 405:
            found.append(("HEAD", f"answered {head.status_code} where the product "
                                  f"answers 405"))

    unused = {"delete", "patch", "put"} - methods
    if unused:
        verb = sorted(unused)[0].upper()
        want_status, want_allow = WRONG_METHOD[mount]
        if mount == "splunk":
            want_status, want_allow = _splunk_expectation(verb, path)
        answer = client.request(verb, url, headers=headers, params=PARAMS[mount])
        if answer.status_code != want_status:
            found.append((f"{verb} it does not take",
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
