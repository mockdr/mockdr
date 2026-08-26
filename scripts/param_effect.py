# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR0911, PLR0912, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Ask every route whether its parameters do anything.

The defect this looks for is the quietest one a mock can have: a route that
*declares* `limit`, `$filter` or `$select`, answers 200, and ignores it. A
client sees a plausible page, believes it filtered, and gets something else
in production — which is exactly the failure mode the conformance harness
was built for, except this one needs no real product to find.

Each parameter is sent a value whose effect is not a matter of taste:

* a limiter (`limit`, `$top`, `count`, `per_page`) set to 1 must not answer
  with two items;
* a skipper (`skip`, `$skip`, `offset`, `from`) past the end must answer
  with none;
* a filter (`filter`, `$filter`, `query`, `ids`, `name__contains` …) given a
  value nothing can match must answer with none;
* `$select=id` must not answer with every field;
* `$count=true` must add a count;
* a sort asked for in both directions must not answer with the same order
  twice, when the collection holds two different values to order by.

A route whose collection is already empty is skipped — there is nothing to
filter — as is one that refuses the baseline request. Exit status 1 when
anything is flagged.

A route may also read a parameter it never *declares* — Elasticsearch's URI
search and Splunk's collection parameters are read straight off the query
string — and those are invisible to a sweep over the OpenAPI schema. They
are listed here per route instead, and exercised the same way. Every one of
them was ignored when the list was first written.

    backend/.venv/bin/python scripts/param_effect.py [mount ...]
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

#: Values that make a path parameter resolve to something the mock holds.
#: A route whose id cannot be resolved answers 404 and is skipped anyway.
_IDS = {
    "web": "1", "cs": "1", "mde": "1", "graph": "1",
}

#: Parameters every route takes for reasons other than filtering.
_STRUCTURAL = {
    "api-version", "output_mode", "format", "pretty", "human", "kbn-xsrf",
    "$expand", "namespace_type", "namespaceType", "keep_alive", "refresh",
    "ignore_unavailable", "allow_no_indices", "expand_wildcards", "scroll",
    "explain", "v", "h", "s", "bytes", "time", "master_timeout", "timeout",
    "wait_for_completion", "conflicts", "slices", "requests_per_second",
    "case_insensitive", "typed_keys", "track_total_hits", "terminate_after",
    "analyzer", "default_operator", "df", "lenient", "_source", "docvalue_fields",
    "stored_fields", "seq_no_primary_term", "version", "sort_key", "sort_dir",
    "sort_mode", "f", "count",  # `count` is Splunk's limiter, checked by name below
}

_LIMITERS = {"limit", "$top", "per_page", "perPage", "pageSize", "page_size",
             "size", "count", "top", "maxResults", "max_results", "num"}
_SKIPPERS = {"skip", "$skip", "offset", "from", "start", "startIndex"}
_SELECTORS = {"$select", "select", "fields", "_source_includes"}
_COUNTERS = {"$count"}
#: A value nothing in the mock can match, in the shapes each vendor's filter
#: language takes.
_IMPOSSIBLE = {
    "$filter": "id eq 'zzz-no-such-value-xyz'",
    "filter": "zzz-no-such-value-xyz",
    "query": "zzz-no-such-value-xyz",
    "q": "zzz-no-such-value-xyz",
    "search": "zzz-no-such-value-xyz",
    "ids": "zzz-no-such-value-xyz",
    "id": "zzz-no-such-value-xyz",
    "sid": "zzz-no-such-value-xyz",
}
_CONTAINS = re.compile(r"__contains$|__like$|Name$|name$")

#: How each vendor spells "sort by this, in this direction". The value is
#: filled in with a field the baseline answer actually varies on.
_SORTERS = {
    "sortBy": ("sortOrder", "{field}", "asc", "desc"),
    "sort_by": ("sort_order", "{field}", "asc", "desc"),
    "sortField": ("sortOrder", "{field}", "asc", "desc"),
    "sort_field": ("sort_order", "{field}", "asc", "desc"),
    "orderBy": (None, "{field} asc", "", ""),
    "$orderby": (None, "{field} asc", "", ""),
    "sort": (None, "{field}.asc", "", ""),
}

#: Where the items live in a vendor's envelope.
_COLLECTION_KEYS = (
    "data", "value", "resources", "items", "entry", "results", "notes",
    "saved_objects", "cases", "rules", "agents", "objects", "list", "records",
)


def collection(body):
    """The list of items in a response, wherever this vendor keeps it."""
    if isinstance(body, list):
        return body if all(isinstance(item, dict) for item in body) else None
    if not isinstance(body, dict):
        return None
    hits = body.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        return hits["hits"]
    for key in _COLLECTION_KEYS:
        found = body.get(key)
        if isinstance(found, list) and (not found or isinstance(found[0], dict)):
            return found
    # Cortex XDR wraps everything one level deeper.
    reply = body.get("reply")
    if isinstance(reply, dict):
        return collection(reply)
    if isinstance(reply, list):
        return reply
    return None


def fill(path, mount):
    def sub(match):
        name = match.group(1).lower()
        if "uuid" in name or name.endswith("_id") or name == "id" or "sid" in name:
            return _IDS.get(mount, str(uuid.uuid4()))
        if "index" in name or "name" in name or "collection" in name:
            return "zzz-conformance"
        return "x"
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", sub, path)


def probe_value(name, kind):
    """What to send this parameter so that ignoring it is visible."""
    lowered = name.lower()
    if name in _LIMITERS or lowered in {n.lower() for n in _LIMITERS}:
        return "1", "limit"
    if name in _SKIPPERS or lowered in {n.lower() for n in _SKIPPERS}:
        return "100000", "skip"
    if name in _SELECTORS:
        return "id", "select"
    if name in _COUNTERS:
        return "true", "count"
    if name in _IMPOSSIBLE:
        return _IMPOSSIBLE[name], "filter"
    if _CONTAINS.search(name) and kind == "string":
        return "zzz-no-such-value-xyz", "filter"
    if name.endswith(("Ids", "_ids", "__in")) or name in ("severities", "statuses", "types"):
        return "zzz-no-such-value-xyz", "filter"
    return None, ""


def sortable_field(items):
    """A field the collection actually varies on, or None."""
    for name in ("id", "name", "displayName", "hostname", "createdAt", "created_at"):
        values = [item.get(name) for item in items if isinstance(item, dict)]
        distinct = {v for v in values if isinstance(v, (str, int, float))}
        if len(distinct) > 1:
            return name
    for name in items[0]:
        values = [item.get(name) for item in items if isinstance(item, dict)]
        distinct = {v for v in values if isinstance(v, (str, int, float))}
        if len(distinct) > 1:
            return name
    return None


def judge(kind, base_items, probe_items, probe_body):
    """Whether the parameter did what its name promises."""
    if kind == "limit":
        return len(probe_items) <= 1
    if kind in ("skip", "filter"):
        return len(probe_items) == 0
    if kind == "select":
        if not probe_items:
            return True
        extra = {k for k in probe_items[0] if not k.startswith(("@", "_"))} - {"id"}
        return not extra
    if kind == "count":
        text = json.dumps(probe_body)
        return '"@odata.count"' in text or '"count"' in text or '"total' in text
    return True


#: Parameters a route reads without declaring them, so no schema sweep can
#: find them: ``(mount, path, {parameter: value}, kind)``, where *kind* is
#: judged exactly as a declared parameter of that kind would be.
_UNDECLARED = [
    ("elastic", "/elastic/logs-endpoint/_search", {"size": "1"}, "limit"),
    ("elastic", "/elastic/logs-endpoint/_search", {"q": _IMPOSSIBLE["q"]}, "filter"),
    # Past every document, but inside the 10 000-result window both the
    # product and the mock refuse to page beyond.
    ("elastic", "/elastic/logs-endpoint/_search",
     {"from": "9000", "size": "10"}, "skip"),
    ("elastic", "/elastic/logs-endpoint/_search", {"_source_includes": "id"}, "select"),
    ("elastic", "/elastic/logs-endpoint/_count", {"q": _IMPOSSIBLE["q"]}, "filter"),
    ("splunk", "/splunk/services/data/indexes",
     {"output_mode": "json", "count": "1"}, "limit"),
    ("splunk", "/splunk/services/data/indexes",
     {"output_mode": "json", "count": "0", "search": _IMPOSSIBLE["search"]}, "filter"),
    ("splunk", "/splunk/services/data/indexes",
     {"output_mode": "json", "count": "0", "offset": "100000"}, "skip"),
    ("splunk", "/splunk/services/saved/searches",
     {"output_mode": "json", "count": "0", "search": _IMPOSSIBLE["search"]}, "filter"),
]


def undeclared():
    """The parameters no schema declares, judged like the ones that are."""
    flags, checked = [], 0
    for mount, path, params, kind in _UNDECLARED:
        headers = AUTH.get(mount)
        if headers is None:
            continue
        base = client.get(path, headers=headers, params={
            k: v for k, v in params.items() if k in ("output_mode",)
        })
        if base.status_code != 200:
            continue
        base_items = collection(base.json())
        if not base_items:
            continue
        checked += 1
        response = client.get(path, headers=headers, params=params)
        if response.status_code != 200:
            flags.append((mount, path, ",".join(params), kind,
                          len(base_items), f"HTTP {response.status_code}"))
            continue
        items = collection(response.json())
        if items is None:
            continue
        if not judge(kind, base_items, items, response.json()):
            flags.append((mount, path, ",".join(params), kind,
                          len(base_items), len(items)))
    return flags, checked


def main():
    wanted = sys.argv[1:]
    flags = []
    checked = 0
    for path, operations in app.openapi()["paths"].items():
        operation = operations.get("get")
        if not operation:
            continue
        mount = path.split("/")[1]
        if wanted and mount not in wanted:
            continue
        headers = AUTH.get(mount)
        if headers is None:
            continue
        parameters = [
            p for p in operation.get("parameters", [])
            if p.get("in") == "query" and p["name"] not in _STRUCTURAL
        ]
        if not parameters:
            continue
        url = fill(path, mount)
        base = client.get(url, headers=headers)
        if base.status_code != 200:
            continue
        try:
            base_body = base.json()
        except ValueError:
            continue
        base_items = collection(base_body)
        if not base_items:
            continue

        for parameter in parameters:
            name = parameter["name"]
            kind_hint = (parameter.get("schema") or {}).get("type", "string")
            value, kind = probe_value(name, kind_hint)
            if not kind:
                continue
            checked += 1
            response = client.get(url, headers=headers, params={name: value})
            if response.status_code != 200:
                continue
            try:
                body = response.json()
            except ValueError:
                continue
            items = collection(body)
            if items is None:
                continue
            if not judge(kind, base_items, items, body):
                flags.append((mount, path, name, kind, len(base_items), len(items)))

        # Ordering is its own question: ask for both directions and see
        # whether the answer moves.
        declared = {p["name"] for p in parameters}
        for name in declared & set(_SORTERS):
            partner, template, ascending, descending = _SORTERS[name]
            field = sortable_field(base_items)
            if field is None:
                continue
            checked += 1
            one = client.get(url, headers=headers, params={
                name: template.format(field=field),
                **({partner: ascending} if partner else {}),
            })
            other = client.get(url, headers=headers, params={
                name: template.format(field=field).replace(".asc", ".desc")
                                                   .replace(" asc", " desc"),
                **({partner: descending} if partner else {}),
            })
            if one.status_code != 200 or other.status_code != 200:
                continue
            try:
                first, second = collection(one.json()), collection(other.json())
            except ValueError:
                continue
            if not first or not second or len(first) < 2:
                continue
            if [i.get(field) for i in first] == [i.get(field) for i in second]:
                flags.append((mount, path, name, "sort", len(first), len(second)))

    found, count = undeclared()
    flags += [f for f in found if not wanted or f[0] in wanted]
    checked += count

    print(f"=== PARAMETER EFFECT === {checked} parameter(s) exercised")
    by_mount = {}
    for mount, path, name, kind, before, after in flags:
        by_mount.setdefault(mount, []).append((path, name, kind, before, after))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for path, name, kind, before, after in sorted(by_mount[mount]):
            print(f"  {kind:<7} {name:<22} {path:<58} {before} → {after}")
    print(f"\n  {len(flags)} parameter(s) with no effect")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
