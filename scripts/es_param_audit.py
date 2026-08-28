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
import os
import sys
import urllib.error
import urllib.request

REAL = os.environ.get("ES_URL", "http://localhost:19200")
MOCK = os.environ.get("MOCKDR", "http://localhost:5001/elastic")
INDEX = os.environ.get("ES_PROBE_INDEX", "conformance-seeded")
REAL_AUTH = "Basic " + base64.b64encode(
    f"elastic:{os.environ.get('ES_PASSWORD', 'Probe-Passw0rd!')}".encode()).decode()
MOCK_AUTH = "Basic " + base64.b64encode(
    f"elastic:{os.environ.get('MOCKDR_PASSWORD', 'mock-elastic-password')}".encode()).decode()

#: Every parameter any of these routes might take. Membership is decided by
#: measurement; this list only has to be a superset worth asking about.
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
)

#: The GET routes this compares. `{i}` stands for the probe index.
ROUTES = (
    "/", "/_cat/health", "/_cat/indices", "/_cluster/health", "/_cluster/health/{i}",
    "/_count", "/_search", "/_search/scroll", "/_security/_authenticate",
    "/_alias/probe-alias", "/_resolve/index/{i}", "/{i}", "/{i}/_alias",
    "/{i}/_count", "/{i}/_doc/probe-doc", "/{i}/_field_caps", "/{i}/_mapping",
    "/{i}/_mapping/field/host", "/{i}/_search", "/{i}/_settings",
    "/{i}/_source/probe-doc", "/{i}/_stats",
)

#: What the cluster says about a parameter it does not know.
_UNRECOGNISED = b"unrecognized parameter"


def _ask(base: str, auth: str, path: str, key: str) -> tuple[int, bytes]:
    req = urllib.request.Request(f"{base}{path}?{key}=1", headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()[:300]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()[:300]
    except Exception as exc:  # noqa: BLE001 - a release tool, not a request path
        # A cluster that hangs up mid-sweep should cost one question, not the run.
        return 0, str(exc)[:80].encode()


def main() -> int:
    """Compare every route's accepted parameters, in both directions."""
    invented: list[str] = []
    ignored: list[str] = []
    asked = 0
    for route in ROUTES:
        path = route.replace("{i}", INDEX)
        known = []
        for key in CANDIDATES:
            code, body = _ask(REAL, REAL_AUTH, path, key)
            asked += 1
            if not (code == 400 and _UNRECOGNISED in body):
                known.append(key)
        for key in known:
            code, body = _ask(MOCK, MOCK_AUTH, path, key)
            if code == 400 and _UNRECOGNISED in body:
                invented.append(f"{route}?{key}")
        code, body = _ask(MOCK, MOCK_AUTH, path, "zzzqqq")
        if not (code == 400 and _UNRECOGNISED in body):
            ignored.append(route)

    print(f"=== ELASTICSEARCH PARAMETERS === {asked} question(s) across "
          f"{len(ROUTES)} route(s)")
    for line in invented:
        print(f"  refused though the cluster accepts it: {line}")
    for line in ignored:
        print(f"  an unknown parameter is still ignored: {line}")
    print(f"\n  {len(invented)} invented refusal(s), {len(ignored)} route(s) still ignoring")
    return 1 if invented or ignored else 0


if __name__ == "__main__":
    sys.exit(main())
