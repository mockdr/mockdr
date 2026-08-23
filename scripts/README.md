# scripts/

Every script prints what it is for at the top of its file; this is the map.

## Run in CI on every push

| Script | Purpose |
|---|---|
| `fetch_swagger.sh` | Download the SentinelOne Management API 2.1 swagger into `data/` (gitignored, 14 MB). |
| `field_drift.py` | Compare the mock's SentinelOne responses with that swagger; exit 1 on a missing or surplus field. |
| `fuzz_parsers.py` | Fuzz the hand-written parsers (SPL, KQL, OData, FQL, ES DSL, HEC) for unintended exceptions. |
| `hostile_probe.py` | Hostile bodies and parameters against every mounted route; flags any plain-text 500 or crash. |

## Run before a release

| Script | Purpose |
|---|---|
| `schema_drift.py <sentinel\|graph\|crowdstrike\|mde\|xdr\|sentinelone>` | Compare responses with the vendored references (`data/vendor-specs/`); prints drift and unjudged routes. |
| `load_test.py` | Concurrent stress test; exit 0 iff p99 < 500 ms and errors < 1 %. |
| `../conformance/` | Splunk / Elasticsearch / Kibana against the real products (see its README). |

## Run when a vendor reference changes

Reducers read an upstream source and write the facts the comparator needs
into `data/vendor-specs/` (sources and licences: `data/vendor-specs/NOTICE.md`).

| Script | Reads | Writes |
|---|---|---|
| `gofalcon_spec.py` | `CrowdStrike/gofalcon` clone | `crowdstrike_gofalcon_reduced.json` |
| `cs_event_streams_spec.py` | `elastic/integrations` clone (pipeline test logs) | `cs_event_streams_reduced.json` (key names only) |
| `mde_docs_spec.py` | `MicrosoftDocs/defender-docs` clone | `mde_docs_reduced.json` |
| `xsoar_samples_spec.py` | `data/vendor-specs/xsoar-samples/` | `xdr_samples_reduced.json`, `xdr_core_samples_reduced.json`, `mde_samples_reduced.json` |
| `cortex_openapi_spec.py` | community Cortex XDR OpenAPI clone | `xdr_openapi_reduced.json` (key paths only) |
| `splunk_ta_samples_spec.py` | `splunk/attack_data` (downloaded) | `splunk_ta_samples_reduced.json` |

Fixture generators turn a reference into the default shape a route is
completed against (`backend/infrastructure/fixtures/`):

| Script | Platform |
|---|---|
| `gen_s1_fixtures.py` | SentinelOne (from the swagger) |
| `gen_arm_fixtures.py` | Sentinel (from the ARM spec) |
| `gen_mde_fixtures.py` | Defender for Endpoint (from the reduced docs) |
| `gen_xdr_fixtures.py` | Cortex XDR (from the recordings) |

Run them from the repository root with the backend's interpreter:
`backend/.venv/bin/python scripts/<name>.py`.

## Release checklist

1. `ci.sh` green locally (the CI mirror).
2. `schema_drift.py` for the six spec-judged platforms: 0 drift, unjudged routes listed and explained.
3. The conformance harness: Splunk 0 findings, Elasticsearch + Kibana 0 findings (ignore the first run on a fresh stack — `store.size` is `null` on a just-created index and the KV store answers 503 while initialising).
4. `load_test.py` passes.
5. Version in `backend/config.py`, `backend/pyproject.toml`, `frontend/package.json`; a `## [x.y.z]` section in CHANGELOG.md (`tests/unit/test_version.py` checks all four).
6. Push, wait for CI on the release commit, then tag `vX.Y.Z` — never before.
