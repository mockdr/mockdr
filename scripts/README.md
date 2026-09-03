# scripts/

Every script prints what it is for at the top of its file; this is the map.

## Run in CI on every push

| Script | Purpose |
|---|---|
| `fetch_swagger.sh` | Download the SentinelOne Management API 2.1 swagger into `data/` (gitignored, 14 MB). |
| `field_drift.py` | Compare the mock's SentinelOne responses with that swagger; exit 1 on a missing or surplus field. |
| `param_drift.py` | Compare the *query parameters* each route takes with the ones the swagger declares — a filter the vendor documents and the mock drops answers 200 with the whole collection. Also counts and lists the *routes* the mock serves that the vendor does not publish. |
| `fuzz_parsers.py` | Fuzz the hand-written parsers (SPL, KQL, OData, FQL, ES DSL, HEC) for unintended exceptions. |
| `hostile_probe.py` | Hostile bodies and parameters against every mounted route; flags any plain-text 500 or crash. |
| `filter_effect.py` | The same question for filters that travel in a *body* — Cortex's `request_data.filters`, Elasticsearch's query DSL — which `param_effect.py` cannot see. Each is sent a value nothing can match *and* one a record holds. Exit 1 on any. |
| `param_effect.py` | Asks every route whether its parameters do anything: a limiter that does not limit, a filter that cannot match and returns everything, a `$select` that projects nothing, a `sortBy` that leaves the order alone — asked once per field the vendor documents as sortable, because guessing one from the record's top level misses every collection whose records are nested. Covers the parameters a route reads *without declaring* — Elasticsearch's URI search, Splunk's collection parameters — which no schema sweep can see. Exit 1 on any. |
| `paging_audit.py` | Walks every collection a page at a time: flags a record that comes back twice, one that never appears, a total that disagrees with the pages, and paging that will not terminate. Exit 1 on any. |
| `roundtrip_audit.py` | Writes something, then asks for it back: a create that drops the body, an update that answers 200 and changes nothing, a delete that leaves the record in the listing. Every other audit here only reads. Exit 1 on any. |
| `unread_params.py` | Reads the *source*: a handler that declares a parameter and never mentions it again answers 200 with something plausible, and the parameter the client sent simply never happened. The one audit here that needs no running mock, and the only one that can see an effect invisible from outside — a `scope` the product requires, a body a route was built to read. Exit 1 on any. |
| `body_audit.py` | Asks every route that *declares* a body whether it reads one: sends an empty object and one carrying a single member the route never declared, and flags the routes that answer 2xx to both. Needs no vendor reference — a route that accepts a body it cannot have meant is wrong whatever the product does. Routes that are right to answer anything are listed in the script with the reason, so exit 1 means something new. |
| `authz_audit.py` | Asks every write route whether a credential without the right to it gets a 2xx — no credential at all, and the read-only one the vendor issues. The mistake in the other direction: a mock that permits what the product refuses. Exit 1 on any. |
| `method_drift.py` | Find a documented method this mock answers 405 to — a verb the vendor publishes and no route takes. |
| `shadowed_routes.py` | Find a route that a route registered before it already answers, so the second never runs. |
| `unreachable_code.py` | Find an application function nothing can reach. |
| `audit_coverage.py` | Say which routes nothing is watching — the one audit whose subject is the other audits. |
| `enum_drift.py` | Find an answer whose value is outside the set the vendor declares. |
| `type_stability_audit.py` | Ask whether a field means the same thing everywhere it appears — a `severity` that is a string here and a number there. |
| `consistency_audit.py` | Fetch the same record two ways and check it is the same record. |
| `causality_audit.py` | Time has to run forwards, in every record this mock serves: nothing is updated before it was created. |
| `dangling_references.py` | Find a record that names a record this install does not have. |
| `error_envelope_audit.py` | Check that every refusal is shaped the way its vendor shapes refusals — a client parses the error path too. |
| `http_contract_audit.py` | Check the HTTP level itself, route by route, against what each runnable product does: content type, `Allow`, `HEAD`, the `WWW-Authenticate` challenge. |
| `rfc_conformance.py` | Check the *protocol* rather than the vendor: 22 normative requirements of RFC 9110, 6749, 6750, 7617 and 8259 that bear on this origin server. Where a product breaks one, the simulation follows it and the deviation is listed with the measurement. |
| `filter_spellings.py` | Ask whether two spellings of one filter select the same records. |
| `write_effect.py` | Ask every write route whether the members it accepts do anything: a body applied in part answers 200 and reads back the old value. |
| `frontend_route_drift.py` | Every route the console calls must be one the mock serves. |
| `frontend_type_drift.py` | Ask whether the console's response types describe the answers it gets — an interface copied from a seeder type-checks perfectly and renders nothing. |
| `frontend_body_drift.py` | Ask whether the members the console writes are members the vendor documents. |
| `frontend_param_drift.py` | Ask whether the query parameters the console sends are ones a route reads. |
| `frontend_value_drift.py` | Ask whether the values the console compares against ever actually occur — a branch on a string no answer carries never runs. |
| `frontend_fixture_drift.py` | Do the frontend's captured fixtures still match what the mock answers? |
| `schema_drift.py <vendor>` | Compare responses with the vendored references (`data/vendor-specs/`); prints drift and unjudged routes. CI runs all six mounts: `crowdstrike`, `mde`, `xdr`, `sentinel`, `graph`, `sentinelone`. |

## Run periodically, not per push

| Script | Purpose |
|---|---|
| `mutation_probe.py` | Measures the gates above rather than the mock: injects one defect at a time — a comparison flipped, a sort reversed, a boundary loosened — and reports which ones nothing notices. The first run caught five of ten; whatever survives is a behaviour no gate is checking. Slow (a suite run per injection), so it belongs in a quiet hour rather than on a push. |

## Run before a release

| Script | Purpose |
|---|---|
| `load_test.py` | Concurrent stress test; exit 0 iff p99 < 500 ms and errors < 1 %. Also a weekly CI job (`conformance.yml`). |
| `../conformance/` | Splunk / Elasticsearch / Kibana against the real products; also a weekly/on-demand CI workflow (`conformance.yml`). |

## Run when a vendor reference changes

Reducers read an upstream source and write the facts the comparator needs
into `data/vendor-specs/` (sources and licences: `data/vendor-specs/NOTICE.md`).

| Script | Reads | Writes |
|---|---|---|
| `gofalcon_spec.py` | `CrowdStrike/gofalcon` clone | `crowdstrike_gofalcon_reduced.json` (200 payloads *and* request bodies) |
| `graph_csdl_spec.py` | a Microsoft Graph CSDL (`microsoftgraph/msgraph-metadata`) | `graph_<version>_csdl_types.json` (type → properties) |
| `cs_event_streams_spec.py` | `elastic/integrations` clone (pipeline test logs) | `cs_event_streams_reduced.json` (key names only) |
| `mde_docs_spec.py` | `MicrosoftDocs/defender-docs` clone | `mde_docs_reduced.json` (route → key paths, entity properties, and each enum's members *in declared order*) |
| `xsoar_samples_spec.py` | `data/vendor-specs/xsoar-samples/` | `xdr_samples_reduced.json`, `xdr_core_samples_reduced.json`, `mde_samples_reduced.json` |
| `cortex_alerts_spec.py` | `elastic/integrations` (downloaded) | `xdr_alerts_multi_events_reduced.json` (key paths only) |
| `cortex_openapi_spec.py` | community Cortex XDR OpenAPI clone | `xdr_openapi_reduced.json` (key paths only) |
| `s1_channel_fields_spec.py` | `splunk/SA-SentinelOneDevices` (downloaded) | `s1_splunk_channel_fields.json` (field names only) |
| `splunk_ta_samples_spec.py` | `splunk/attack_data` (downloaded) | `splunk_ta_samples_reduced.json` (key paths, the JSON type each was seen holding, and which were seen null) |

Fixture generators turn a reference into the default shape a route is
completed against (`backend/infrastructure/fixtures/`):

| Script | Platform |
|---|---|
| `gen_s1_fixtures.py` | SentinelOne (from the swagger) |
| `gen_arm_fixtures.py` | Sentinel (from the ARM spec) |
| `gen_mde_fixtures.py` | Defender for Endpoint (from the reduced docs) |
| `gen_xdr_fixtures.py` | Cortex XDR (from the recordings) |
| `gen_documented_bodies.py` | SentinelOne (swagger) and CrowdStrike (gofalcon) — what each write body must carry (`backend/application/documented_bodies.py`); the guard that reads it refuses a body carrying nothing the route knows. |

Run them from the repository root with the backend's interpreter:
`backend/.venv/bin/python scripts/<name>.py`.

## Release checklist

1. `ci.sh` green locally (the CI mirror).
2. `schema_drift.py` for the six spec-judged platforms: 0 drift, unjudged routes listed and explained.
3. The conformance harness: Splunk 0 findings, Elasticsearch + Kibana 0 findings (ignore the first run on a fresh stack — `store.size` is `null` on a just-created index and the KV store answers 503 while initialising).
4. `load_test.py` passes.
5. Version in `backend/config.py`, `backend/pyproject.toml`, `frontend/package.json`; a `## [x.y.z]` section in CHANGELOG.md (`tests/unit/test_version.py` checks all four).
6. Push, then tag `vX.Y.Z` — never before the checks above are green.

   GitHub Actions is disabled on this repository, so there is no CI run to
   wait for and this step does not pretend there is. `ci.sh` stands in its
   place, and since it now reads its audit list out of `ci.yml` rather than
   carrying a copy, it runs the same checks: both quality gates, the
   browser suite, all thirty-four audit invocations, the Docker build and
   its smoke test. What it does *not* cover, and what therefore does not run
   for a release made this way: the Trivy container scan, the SBOM, and
   gitleaks — the last only because it is not installed here. Turning the
   workflow back on for a release commit (`gh workflow enable "CI"`) is the
   way to get those; 2.4.0 shipped without them, deliberately.
7. `gh release create vX.Y.Z --title "mockdr vX.Y.Z" --notes-file <the CHANGELOG section> --verify-tag` — a tag without a Release is invisible to anyone reading the repository page (2.1.0 shipped that way).
