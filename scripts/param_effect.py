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
* a parameter that shapes the *answer* — `pretty`, `filter_path`, `bytes`,
  a `format` or `output_mode` that names a renderer — must change it;
* a sort asked for in both directions must not answer with the same order
  twice, when the collection holds two different values to order by — asked
  once per field the vendor documents as sortable, because guessing one from
  the record's top level misses every collection whose records are nested.

A route whose collection is already empty is skipped — there is nothing to
filter — as is one that refuses the baseline request. Exit status 1 when
anything is flagged.

A route may also read a parameter it never *declares* — Elasticsearch's URI
search and Splunk's collection parameters are read straight off the query
string — and those are invisible to a sweep over the OpenAPI schema. They
are listed here per route instead, and exercised the same way. Every one of
them was ignored when the list was first written.

The run prints its own denominator. "0 parameters with no effect" says
nothing about a route this script never reached, and 38 of them are not
reached: a path parameter it cannot resolve (`{sid}`, `{case_id}`,
`{index}`), or a required query parameter it does not supply. Their
declarations were read before that was accepted — they are `$select`,
`page`, `per_page`, `count`, `offset`, `ids`, `queryId`, `cursor`, `limit`,
almost all of them structural and excluded here anyway, with `paging_audit`
covering the rest. The blind spot is smaller than the number, and the number
is printed either way.

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
#: Parameters that shape the *answer* rather than select records. They were
#: all filed under "structural" and exercised by nothing, which is how four
#: of them — `filter_path`, `pretty`, `bytes` and the `_cat` `format` — were
#: declared and ignored for as long as they were. Each is sent with a value
#: whose effect can be judged from the answer alone.
#: These are read off the query string by the product rather than declared
#: per route, so requiring a declaration would skip every one of them — the
#: same blind spot one level down. Each entry says which paths it applies to.
_SHAPERS = (
    # (path predicate, parameter, value, how to tell it worked)
    # `_cat` answers a text table, which neither of these shapes — measured:
    # `pretty` and `filter_path` do nothing there unless `format=json` turns
    # the answer into a document first.
    (lambda p: p.startswith("/elastic/") and "/_cat/" not in p,
     "pretty", "", "indented"),
    (lambda p: p.startswith("/elastic/") and "/_cat/" not in p,
     "filter_path", "zzz-nothing-matches-this", "empty-document"),
    (lambda p: p.startswith("/elastic/_cat/"), "format", "json", "json"),
    (lambda p: p.startswith("/elastic/_cat/"), "bytes", "b", "no-units"),
    (lambda p: p.startswith("/splunk/services/"), "output_mode", "json", "json"),
)

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


#: The vendor's own list of what a collection can be ordered by. mockdr
#: declares `sortBy` as a plain string, so the enum lives only in the
#: swagger — and without it this fell back to guessing a field from the
#: record's top level, which is empty of sortable members on every
#: collection whose records are nested.
_SWAGGER = Path(__file__).resolve().parents[1] / "data" / "swagger_2_1.json"


def documented_sort_fields():
    """`(path, parameter) -> [field]`, from the swagger if it is there."""
    if not _SWAGGER.exists():
        return {}
    spec = json.loads(_SWAGGER.read_text())
    out = {}
    for path, operations in spec.get("paths", {}).items():
        for parameter in (operations.get("get") or {}).get("parameters", []):
            if parameter.get("enum") and parameter.get("name") in _SORTERS:
                out[(path, parameter["name"])] = parameter["enum"]
    return out


def _anywhere(item, name):
    """The value of *name* on this record, top level or one level in."""
    if not isinstance(item, dict):
        return None
    if name in item:
        return item[name]
    for value in item.values():
        if isinstance(value, dict) and name in value:
            return value[name]
    return None


def varies(items, name):
    """Whether a field is worth ordering by: at least two distinct values."""
    distinct = {
        v for v in (_anywhere(i, name) for i in items)
        if isinstance(v, (str, int, float))
    }
    return len(distinct) > 1


def sortable_fields(items, declared):
    """The fields to ask this collection to order by.

    The names the *vendor* documents come first: guessing one from the
    record's own top level missed every collection whose records are nested,
    and a threat keeps everything worth sorting on inside `threatInfo` — so
    fifteen documented sort fields could be asked for and ignored without
    this ever looking at one of them.
    """
    documented = [name for name in declared if varies(items, name)]
    if documented:
        return documented
    for name in ("id", "name", "displayName", "hostname", "createdAt", "created_at"):
        if varies(items, name):
            return [name]
    return [name for name in items[0] if varies(items, name)][:1]


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


DOCUMENTED_SORTS = documented_sort_fields()


def shaping(wanted):
    """Ask the answer-shaping parameters whether they shape the answer."""
    flags, checked = [], 0
    for path, operations in app.openapi()["paths"].items():
        operation = operations.get("get")
        if not operation or "/_dev/" in path:
            continue
        mount = path.split("/")[1]
        if (wanted and mount not in wanted) or AUTH.get(mount) is None:
            continue
        url = fill(path, mount)
        for applies, name, value, judgment in _SHAPERS:
            if not applies(path):
                continue
            base = client.get(url, headers=AUTH[mount])
            if base.status_code != 200:
                continue
            shaped = client.get(url, headers=AUTH[mount], params={name: value})
            if shaped.status_code != 200:
                continue
            checked += 1
            if not _shaped(judgment, base, shaped):
                flags.append((mount, path, name, "shape", judgment, "unchanged"))
    return flags, checked


def _shaped(judgment, base, shaped):
    """Whether the answer changed the way this parameter promises."""
    if judgment == "indented":
        return b"\n" in shaped.content and b"\n" not in base.content
    if judgment == "empty-document":
        return shaped.content.strip() in (b"{}", b"[]")
    if judgment == "json":
        try:
            shaped.json()
        except ValueError:
            return False
        return True
    if judgment == "no-units":
        text = shaped.text
        return not any(unit in text for unit in ("kb", "mb", "gb"))
    return True


def main():
    wanted = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "--verbose" in sys.argv
    flags = []
    unreachable: dict[str, list[str]] = {}
    empty: dict[str, list[str]] = {}
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
            # A path parameter this script cannot resolve answers 404 and the
            # route drops out silently. `_IDS` names an id for four mounts;
            # the other five get a random uuid, so every parameterised route
            # on them was skipped while the summary still read "0 with no
            # effect" — a count with no denominator, which is the shape of an
            # audit that has stopped looking.
            unreachable.setdefault(mount, []).append(f"{path} -> {base.status_code}")
            continue
        try:
            base_body = base.json()
        except ValueError:
            unreachable.setdefault(mount, []).append(f"{path} -> not JSON")
            continue
        base_items = collection(base_body)
        if not base_items:
            empty.setdefault(mount, []).append(path)
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
            values = DOCUMENTED_SORTS.get((path, name), [])
            for field in sortable_fields(base_items, values):
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
                if ([_anywhere(i, field) for i in first]
                        == [_anywhere(i, field) for i in second]):
                    flags.append((mount, f"{path} [{field}]", name, "sort",
                                  len(first), len(second)))

    found, count = undeclared()
    flags += [f for f in found if not wanted or f[0] in wanted]
    checked += count

    shaped_flags, shaped_count = shaping(wanted)
    flags += shaped_flags
    checked += shaped_count

    print(f"=== PARAMETER EFFECT === {checked} parameter(s) exercised")
    by_mount = {}
    for mount, path, name, kind, before, after in flags:
        by_mount.setdefault(mount, []).append((path, name, kind, before, after))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for path, name, kind, before, after in sorted(by_mount[mount]):
            print(f"  {kind:<7} {name:<22} {path:<58} {before} → {after}")
    print(f"\n  {len(flags)} parameter(s) with no effect")

    # The denominator. "0 with no effect" over routes this script could not
    # reach says nothing about them, and saying so is the point.
    skipped = sum(len(v) for v in unreachable.values())
    hollow = sum(len(v) for v in empty.values())
    print(f"  {skipped} route(s) not reached: a path parameter this script "
          f"cannot resolve, or a refusal")
    for mount in sorted(unreachable):
        print(f"      {mount}: {len(unreachable[mount])}")
        if verbose:
            for entry in sorted(unreachable[mount]):
                print(f"        {entry}")
    print(f"  {hollow} route(s) whose collection is empty, so nothing could be narrowed")
    for mount in sorted(empty):
        print(f"      {mount}: {len(empty[mount])}")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
