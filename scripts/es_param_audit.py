"""Which query parameters a cluster knows, and whether mockdr agrees.

Elasticsearch refuses a parameter it does not recognise, and mockdr used to
ignore it and answer 200 — so a client that wrote `siz` for `size` read an
unfiltered result set as a filtered one. Imitating the refusal needs the
accepted set for every route, and getting that set *wrong in the other
direction* invents a 400 the cluster never answers, which is just as bad.

So this asks the cluster itself, one parameter at a time, and checks mockdr
in both directions:

  * every parameter the cluster accepts, mockdr must not refuse;
  * a parameter neither of them knows, mockdr must refuse.

The oracle is the message, not the status: the cluster calls an unrecognised
parameter unrecognised, and complains about the *value* of a known one — so
`?sort=1` is a 400 about a known parameter and `?zzz=1` a 400 about an
unknown one. Reading the status alone confuses the two, and a candidate list
built that way once left `ignore_unavailable` off `_stats`.

    python scripts/es_param_audit.py

Needs a real Elasticsearch (`ES_URL`, default localhost:19200) and mockdr
(`MOCKDR`, default localhost:5001/elastic).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

REAL = os.environ.get("ES_URL", "http://localhost:19200")
MOCK = os.environ.get("MOCKDR", "http://localhost:5001/elastic")
#: This script makes and drops its own index: a destructive route asked about
#: a parameter it *does* take performs the action, so it must never be aimed
#: at anything the rest of the harness needs.
INDEX = os.environ.get("ES_PROBE_INDEX", "mockdr-param-probe")
REAL_AUTH = "Basic " + base64.b64encode(
    f"elastic:{os.environ.get('ES_PASSWORD', 'Probe-Passw0rd!')}".encode()).decode()
MOCK_AUTH = "Basic " + base64.b64encode(
    f"elastic:{os.environ.get('MOCKDR_PASSWORD', 'mock-elastic-password')}".encode()).decode()

#: Every parameter any of these routes might take. Membership is decided by
#: measurement; this list only has to be a superset worth asking about — and
#: it has to be a *generous* one. A first version left out `index` and `name`,
#: which nearly every route takes as an alias for its own path segment, and
#: the audit reported agreement it had never asked about.
CANDIDATES = (
    "_source", "_source_excludes", "_source_includes", "allow_no_indices",
    "allow_partial_search_results", "analyze_wildcard", "analyzer",
    "batched_reduce_size", "bytes", "ccs_minimize_roundtrips", "completion_fields",
    "default_operator", "df", "docvalue_fields", "error_trace", "expand_wildcards",
    "explain", "features", "fielddata_fields", "fields", "filter_path", "filters",
    "flat_settings", "forbid_closed_indices", "force_synthetic_source", "format",
    "from", "groups", "h", "health", "help", "human", "ignore_throttled",
    "ignore_unavailable", "include_defaults", "include_empty_fields",
    "include_named_queries_score", "include_segment_file_sizes",
    "include_unloaded_segments", "include_unmapped", "lenient", "level", "local",
    "master_timeout", "max_concurrent_shard_requests", "metric",
    "min_compatible_shard_node", "min_score", "mode", "pre_filter_shard_size",
    "preference", "pretty", "pri", "q", "realtime", "refresh", "request_cache",
    "rest_total_hits_as_int", "routing", "s", "scroll", "scroll_id", "search_type",
    "seq_no_primary_term", "size", "sort", "source", "stats", "stored_fields",
    "suggest_field", "suggest_mode", "suggest_size", "suggest_text",
    "terminate_after", "time", "timeout", "track_scores", "track_total_hits", "ts",
    "types", "typed_keys", "v", "version", "version_type", "wait_for_active_shards",
    "wait_for_events", "wait_for_no_initializing_shards",
    "wait_for_no_relocating_shards", "wait_for_nodes", "wait_for_status",
    # The two that name what the path already names, and the members the
    # write routes add on top.
    "index", "name", "all_shards", "conflicts", "flush", "force", "if_primary_term",
    "if_seq_no", "keep_alive", "max_docs", "max_num_segments", "only_expunge_deletes",
    "op_type", "pipeline", "requests_per_second", "retry_on_conflict", "rewrite",
    "scroll_size", "slices", "source_content_type", "wait_for_completion",
    "wait_if_ongoing",
)

#: The routes this compares, as (method, path). `{i}` stands for the probe
#: index. A refusal precedes the action — measured: a `DELETE` of a document
#: with an unrecognised parameter leaves the document there — so asking a
#: write route about a parameter it does *not* take is safe. Asking about one
#: it does take is not, which is why the destructive routes are asked last
#: and against an index this script makes and drops itself.
ROUTES = (
    ("GET", "/"), ("GET", "/_cat/health"), ("GET", "/_cat/indices"),
    ("GET", "/_cluster/health"), ("GET", "/_cluster/health/{i}"), ("GET", "/_count"),
    ("GET", "/_search"), ("GET", "/_search/scroll"), ("GET", "/_security/_authenticate"),
    ("GET", "/_alias/probe-alias"), ("GET", "/_resolve/index/{i}"), ("GET", "/{i}"),
    ("GET", "/{i}/_alias"), ("GET", "/{i}/_count"), ("GET", "/{i}/_doc/probe-doc"),
    ("GET", "/{i}/_field_caps"), ("GET", "/{i}/_mapping"),
    ("GET", "/{i}/_mapping/field/host"), ("GET", "/{i}/_search"),
    ("GET", "/{i}/_settings"), ("GET", "/{i}/_source/probe-doc"), ("GET", "/{i}/_stats"),
    ("POST", "/_count"), ("POST", "/_search"), ("POST", "/_search/scroll"),
    ("POST", "/{i}/_cache/clear"), ("POST", "/{i}/_count"), ("POST", "/{i}/_field_caps"),
    ("POST", "/{i}/_flush"), ("POST", "/{i}/_forcemerge"), ("POST", "/{i}/_pit"),
    ("POST", "/{i}/_refresh"), ("POST", "/{i}/_search"), ("POST", "/{i}/_update/probe-doc"),
    ("POST", "/{i}/_validate/query"), ("POST", "/{i}/_update_by_query"),
    ("POST", "/{i}/_delete_by_query"), ("PUT", "/{i}/_alias/probe-alias"),
    ("DELETE", "/_search/scroll"), ("DELETE", "/{i}/_alias/probe-alias"),
    ("DELETE", "/{i}/_doc/probe-doc"), ("PUT", "/{i}"), ("DELETE", "/{i}"),
)

#: What the cluster says about a parameter it does not know.
_UNRECOGNISED = b"unrecognized parameter"


def _ask(
    base: str, auth: str, path: str, key: str, method: str = "GET",
) -> tuple[int, bytes]:
    req = urllib.request.Request(
        f"{base}{path}?{key}=1", method=method, headers={"Authorization": auth},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()[:300]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()[:300]
    except Exception as exc:  # noqa: BLE001 - a release tool, not a request path
        # A cluster that hangs up mid-sweep should cost one question, not the run.
        return 0, str(exc)[:80].encode()


#: The routes that act, and so need the probe index put back first.
_DESTRUCTIVE = frozenset({
    ("POST", "/{i}/_update_by_query"), ("POST", "/{i}/_delete_by_query"),
    ("PUT", "/{i}/_alias/probe-alias"), ("DELETE", "/{i}/_alias/probe-alias"),
    ("DELETE", "/{i}/_doc/probe-doc"), ("PUT", "/{i}"), ("DELETE", "/{i}"),
})


def _write(base: str, auth: str, method: str, path: str, body: object = None) -> None:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{base}{path}", method=method, data=data,
        headers={"Authorization": auth, **({"Content-Type": "application/json"} if data else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=25):
            return
    except Exception:  # noqa: BLE001, S110 - a release tool; "already gone" is fine
        pass


def _rebuild() -> None:
    """Put the probe index, its document and its alias back on both sides."""
    for base, auth in ((REAL, REAL_AUTH), (MOCK, MOCK_AUTH)):
        _write(base, auth, "DELETE", f"/{INDEX}")
        _write(base, auth, "PUT", f"/{INDEX}",
               {"settings": {"number_of_shards": 1, "number_of_replicas": 0}})
        _write(base, auth, "PUT", f"/{INDEX}/_doc/probe-doc?refresh=true", {"host": "probe"})
        _write(base, auth, "PUT", f"/{INDEX}/_alias/probe-alias")


def main() -> int:
    """Compare every route's accepted parameters, in both directions."""
    invented: list[str] = []
    ignored: list[str] = []
    asked = 0
    _rebuild()
    for method, route in ROUTES:
        path = route.replace("{i}", INDEX)
        destructive = (method, route) in _DESTRUCTIVE
        for key in (*CANDIDATES, "zzzqqq"):
            if destructive:
                _rebuild()
            code, body = _ask(REAL, REAL_AUTH, path, key, method)
            asked += 1
            theirs = code == 400 and _UNRECOGNISED in body
            code, body = _ask(MOCK, MOCK_AUTH, path, key, method)
            ours = code == 400 and _UNRECOGNISED in body
            if ours and not theirs:
                invented.append(f"{method} {route}?{key}")
            elif theirs and not ours:
                ignored.append(f"{method} {route}?{key}")

    print(f"=== ELASTICSEARCH PARAMETERS === {asked} question(s) across "
          f"{len(ROUTES)} route(s)")
    for line in invented:
        print(f"  refused though the cluster accepts it: {line}")
    for line in ignored:
        print(f"  ignored though the cluster refuses it: {line}")
    print(f"\n  {len(invented)} invented refusal(s), "
          f"{len(ignored)} parameter(s) ignored that the cluster refuses")
    for base, auth in ((REAL, REAL_AUTH), (MOCK, MOCK_AUTH)):
        _write(base, auth, "DELETE", f"/{INDEX}")
    return 1 if invented or ignored else 0


if __name__ == "__main__":
    sys.exit(main())
