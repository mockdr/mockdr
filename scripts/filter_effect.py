# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Ask every filter that travels in a *body* whether it does anything.

`param_effect.py` asks the same question of query parameters, and found
twelve that did nothing. It cannot see this half of the surface: Cortex XDR
is a POST-only API whose every list route takes its filters in
`request_data.filters`, and Elasticsearch's whole query language is a body.
That blind spot cost nine of Cortex's thirteen endpoint filter fields —
each one silently ignored, so a client narrowing to one endpoint was handed
the whole estate with a 200.

Every declared filter is exercised in both directions, because one direction
is not enough:

* given a value **nothing can match**, the answer must be empty — a filter
  that is ignored fails here;
* given a value **taken from a record that is there**, the answer must not
  be empty — a filter that refuses everything passes the first test while
  being just as broken. A field mapped onto a record key nothing holds has
  no such value, and is reported for that: it can only ever answer nothing,
  and would otherwise pass both directions for the wrong reason.

The declarations come from the mock itself: Cortex's field maps, and the
clause builders Elasticsearch's DSL registers. Auditing a mock against its
own claims is the point — a route that advertises a filter and ignores it is
lying to every client that reads its documentation.

    backend/.venv/bin/python scripts/filter_effect.py [xdr|elastic]
"""

import base64
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

XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}
ELASTIC = {"Authorization": "Basic " + base64.b64encode(
    b"elastic:mock-elastic-password").decode()}

#: A value no record holds, in the shapes a filter takes it.
IMPOSSIBLE = "zzz-no-such-value-xyz"


# ── Cortex XDR: request_data.filters ────────────────────────────────────────

def xdr_routes():
    """Each POST list route, its field map, and where its records live."""
    from application.xdr_alerts.queries import _ALERT_FILTER_FIELDS
    from application.xdr_endpoints.queries import _ENDPOINT_FILTER_FIELDS
    from application.xdr_incidents.queries import _INCIDENT_FILTER_FIELDS

    return [
        ("/xdr/public_api/v1/alerts/get_alerts_by_filter_data/",
         _ALERT_FILTER_FIELDS, "alerts"),
        ("/xdr/public_api/v1/incidents/get_incidents/",
         _INCIDENT_FILTER_FIELDS, "incidents"),
        ("/xdr/public_api/v1/endpoints/get_endpoint/",
         _ENDPOINT_FILTER_FIELDS, "endpoints"),
    ]


def xdr_ask(path, filters):
    """Send one filter block and report how many records came back."""
    response = client.post(path, headers=XDR,
                           json={"request_data": {"filters": filters}})
    if response.status_code != 200:
        return None, response.status_code
    reply = response.json().get("reply")
    if not isinstance(reply, dict):
        return None, response.status_code
    for value in reply.values():
        if isinstance(value, list):
            return len(value), 200
    return None, 200


def audit_xdr():
    """Every Cortex filter field, in both directions."""
    flags, checked = [], 0
    for path, fields, key in xdr_routes():
        total, status = xdr_ask(path, [])
        if total is None:
            flags.append((path, "(baseline)", f"answered {status}, not a list"))
            continue
        records = client.post(path, headers=XDR, json={"request_data": {}},
                              ).json()["reply"][key]
        for field, record_key in sorted(fields.items()):
            checked += 1
            # Nothing can match this.
            empty, _ = xdr_ask(path, [
                {"field": field, "operator": "in", "value": [IMPOSSIBLE]},
            ])
            if empty:
                flags.append((path, field,
                              f"a value nothing holds answered {empty} of {total}"))

            # And a value one of the records does hold.
            held = next(
                (r[record_key] for r in records
                 if isinstance(r.get(record_key), (str, int)) and r[record_key] != ""),
                None,
            )
            if held is None:
                held = next(
                    (r[record_key][0] for r in records
                     if isinstance(r.get(record_key), list) and r[record_key]),
                    None,
                )
            if held is None:
                # No record holds the key this field maps onto, so the filter
                # can only ever answer nothing — and the "impossible"
                # direction passes for exactly the wrong reason. A field map
                # pointing at a key the records do not have is the defect,
                # not the absence of a value to test with.
                flags.append((path, field,
                              f"no record holds {record_key!r}, so this filter "
                              f"can only answer nothing"))
                continue
            some, _ = xdr_ask(path, [
                {"field": field, "operator": "in", "value": [held]},
            ])
            if not some:
                flags.append((path, field,
                              f"a value a record holds ({held!r}) answered nothing"))
    return flags, checked


# ── Elasticsearch: the query DSL ────────────────────────────────────────────

#: One clause of each kind the mock registers, in the two directions. The
#: field is `hostname`, which every seeded endpoint document carries.
_INDEX = "logs-endpoint"
_FIELD = "hostname"


def es_clauses(held):
    """Each clause kind, as ``(name, matches, matches-nothing)``."""
    part = held[:4]
    return {
        "match_all": ({"match_all": {}}, None),
        "match": ({"match": {_FIELD: held}}, {"match": {_FIELD: IMPOSSIBLE}}),
        "match_phrase": ({"match_phrase": {_FIELD: held}},
                         {"match_phrase": {_FIELD: IMPOSSIBLE}}),
        "term": ({"term": {_FIELD: held}}, {"term": {_FIELD: IMPOSSIBLE}}),
        "terms": ({"terms": {_FIELD: [held, IMPOSSIBLE]}},
                  {"terms": {_FIELD: [IMPOSSIBLE]}}),
        "range": ({"range": {"enrolled_at": {"gte": "2000-01-01"}}},
                  {"range": {"enrolled_at": {"gte": "2999-01-01"}}}),
        "wildcard": ({"wildcard": {_FIELD: f"{part}*"}},
                     {"wildcard": {_FIELD: f"{IMPOSSIBLE}*"}}),
        "exists": ({"exists": {"field": _FIELD}},
                   {"exists": {"field": "zzz_no_such_field"}}),
        "bool": ({"bool": {"must": [{"term": {_FIELD: held}}]}},
                 {"bool": {"must": [{"term": {_FIELD: IMPOSSIBLE}}]}}),
        "query_string": ({"query_string": {"query": f'{_FIELD}:"{held}"'}},
                         {"query_string": {"query": f'{_FIELD}:"{IMPOSSIBLE}"'}}),
        "prefix": ({"prefix": {_FIELD: part}}, {"prefix": {_FIELD: IMPOSSIBLE}}),
        "regexp": ({"regexp": {_FIELD: f"{part}.*"}},
                   {"regexp": {_FIELD: f"{IMPOSSIBLE}.*"}}),
        "fuzzy": ({"fuzzy": {_FIELD: {"value": held, "fuzziness": 1}}},
                  {"fuzzy": {_FIELD: {"value": IMPOSSIBLE, "fuzziness": 1}}}),
        "multi_match": ({"multi_match": {"query": held, "fields": [_FIELD, "host_os_name"]}},
                        {"multi_match": {"query": IMPOSSIBLE,
                                         "fields": [_FIELD, "host_os_name"]}}),
        "simple_query_string": ({"simple_query_string": {"query": held,
                                                         "fields": [_FIELD]}},
                                {"simple_query_string": {"query": IMPOSSIBLE,
                                                         "fields": [_FIELD]}}),
        "match_phrase_prefix": ({"match_phrase_prefix": {_FIELD: part}},
                                {"match_phrase_prefix": {_FIELD: IMPOSSIBLE}}),
        "match_bool_prefix": ({"match_bool_prefix": {_FIELD: part}},
                              {"match_bool_prefix": {_FIELD: IMPOSSIBLE}}),
        "terms_set": ({"terms_set": {_FIELD: {"terms": [held],
                                              "minimum_should_match_script":
                                                  {"source": "1"}}}},
                      {"terms_set": {_FIELD: {"terms": [IMPOSSIBLE],
                                              "minimum_should_match_script":
                                                  {"source": "1"}}}}),
        "constant_score": ({"constant_score": {"filter": {"term": {_FIELD: held}}}},
                           {"constant_score": {"filter": {"term": {_FIELD: IMPOSSIBLE}}}}),
        "dis_max": ({"dis_max": {"queries": [{"term": {_FIELD: held}}]}},
                    {"dis_max": {"queries": [{"term": {_FIELD: IMPOSSIBLE}}]}}),
        "boosting": ({"boosting": {"positive": {"term": {_FIELD: held}},
                                   "negative": {"term": {_FIELD: IMPOSSIBLE}},
                                   "negative_boost": 0.5}},
                     {"boosting": {"positive": {"term": {_FIELD: IMPOSSIBLE}},
                                   "negative": {"term": {_FIELD: held}},
                                   "negative_boost": 0.5}}),
        "ids": ({"ids": {"values": ["__the_first_id__"]}},
                {"ids": {"values": [IMPOSSIBLE]}}),
    }


def es_hits(query):
    """How many documents a query matches, or None if it was refused."""
    response = client.post(f"/elastic/{_INDEX}/_search", headers=ELASTIC,
                           json={"size": 0, "query": query})
    if response.status_code != 200:
        return None
    return response.json().get("hits", {}).get("total", {}).get("value")


def audit_elastic():
    """Every clause the DSL registers, in both directions."""
    from utils.es_query import _BUILDERS, _WRAPPERS

    flags, checked = [], 0
    first = client.post(f"/elastic/{_INDEX}/_search", headers=ELASTIC,
                        json={"size": 1}).json()["hits"]["hits"][0]
    held = first["_source"][_FIELD]
    total = es_hits({"match_all": {}})

    clauses = es_clauses(held)
    for name, (matching, impossible) in clauses.items():
        matching = _with_id(matching, first["_id"])
        checked += 1
        some = es_hits(matching)
        if some is None:
            flags.append((f"{name}", "matching", "the query was refused"))
        elif not some:
            flags.append((f"{name}", "matching", "a query that must match answered nothing"))
        if impossible is None:
            continue
        none = es_hits(impossible)
        if none is None:
            flags.append((f"{name}", "impossible", "the query was refused"))
        elif none:
            flags.append((f"{name}", "impossible",
                          f"a query nothing can match answered {none} of {total}"))

    # A clause the registry knows and this audit does not is a gap in the
    # audit, and worth saying so rather than passing quietly.
    for name in sorted((set(_BUILDERS) | set(_WRAPPERS)) - set(clauses)):
        flags.append((name, "(unaudited)", "the DSL registers it and this audit does not"))
    return flags, checked


def _with_id(query, doc_id):
    if isinstance(query, dict) and "ids" in query:
        return {"ids": {"values": [doc_id]}}
    return query


def main():
    wanted = sys.argv[1:]
    flags, checked = [], 0
    if not wanted or "xdr" in wanted:
        found, count = audit_xdr()
        flags += [("xdr", *f) for f in found]
        checked += count
    if not wanted or "elastic" in wanted:
        found, count = audit_elastic()
        flags += [("elastic", *f) for f in found]
        checked += count

    print(f"=== FILTER EFFECT === {checked} body filter(s) exercised, both directions")
    by_mount = {}
    for mount, where, what, why in flags:
        by_mount.setdefault(mount, []).append((where, what, why))
    for mount in sorted(by_mount):
        print(f"\n── {mount} ({len(by_mount[mount])})")
        for where, what, why in sorted(by_mount[mount]):
            print(f"  {what:<12} {where:<58}\n      {why}")
    print(f"\n  {len(flags)} filter(s) that do not filter")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
