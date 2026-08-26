# Third-party references under `data/vendor-specs/`

mockdr's response shapes are measured against public references. What is
vendored here, where it came from, and under which terms:

| Files | Source | Licence | What is kept |
|---|---|---|---|
| `sentinel_2024-03-01_*.json`, `sentinel_2025-10-01-preview_openapi.json`, `sentinel-common/`, `common-types/` | `github.com/Azure/azure-rest-api-specs` (`specification/securityinsights/…`) | MIT | The specs as published |
| `graph_v1.0_reduced.json`, `graph_v1.0_types.json`, `graph_beta_reduced.json` | `github.com/microsoftgraph/msgraph-metadata` (`openapi/v1.0`, `openapi/beta`) | MIT | Reduced to route → schema key paths |
| `graph_beta_csdl_types.json`, `graph_v1.0_csdl_types.json` | `github.com/microsoftgraph/msgraph-metadata` (`clean_beta_metadata/`, `clean_v10_metadata/cleanMetadata.xml`) | MIT | Type → property names, Edm types and enum members, for the closure over the types the mock serves: `tiIndicator` from beta (Microsoft retired it from v1.0 and removed the type with it) and `security.deviceEvidence` from v1.0 (`scripts/graph_csdl_spec.py`) |
| `crowdstrike_gofalcon_reduced.json` | `github.com/CrowdStrike/gofalcon` (generated from the Falcon swagger) | MIT | Reduced to operation → 200-payload key paths, plus what each write route *accepts* — `request`, `request_paths`, `request_required` (`scripts/gofalcon_spec.py`). The same repository's `falcon/api_client.go` is the reference for the two rate-limit headers the mock sends on `/cs`; nothing from it is vendored. |
| `cs_event_streams_reduced.json` | `github.com/elastic/integrations`, `packages/crowdstrike/data_stream/falcon/_dev/test/pipeline/*.log` | Elastic License 2.0 | **Key names per event type only** — no recorded events are vendored (`scripts/cs_event_streams_spec.py`) |
| `mde_docs_reduced.json` | `github.com/MicrosoftDocs/defender-docs`, `defender-endpoint/api/*.md` | CC BY 4.0 (docs) | Reduced to route → example key paths, entity property names, and each enum's members in the order the properties table declares them — which is the order OData sorts by (`scripts/mde_docs_spec.py`) |
| `xsoar-samples/`, `xdr_samples_reduced.json`, `xdr_core_samples_reduced.json`, `mde_samples_reduced.json` | `github.com/demisto/content`, `Packs/*/Integrations/*/test_data/` | MIT | Recorded responses as published (see `xsoar-samples/README.md`), plus their key paths |
| `xdr_openapi_reduced.json` | `github.com/tommynsong/cortex-mcp-custom-tools-openapi` (community transcription of the Cortex XDR reference) | **No licence** | **Key paths only** — nothing from the repository is vendored (`scripts/cortex_openapi_spec.py`) |
| `xdr_alerts_multi_events_reduced.json` | `github.com/elastic/integrations`, `packages/panw_cortex_xdr/data_stream/alerts/_dev/deploy/docker/http-mock-config.yml` (Elastic's transcription of `get_alerts_multi_events` replies, placeholder values) | Elastic License 2.0 | **Key paths only** (`scripts/cortex_alerts_spec.py`) |
| `xdr_connector_reduced.json` | MIT-licensed connector code, one cited source per route (see the file's `_provenance`) | MIT | Key paths only |
| `s1_splunk_channel_fields.json` | `github.com/splunk/SA-SentinelOneDevices`, `default/savedsearches.conf` (the fields Splunk's SA reads from `sentinelone:channel:agents`) | **No licence** | **Field names only** (`scripts/s1_channel_fields_spec.py`) |
| `splunk_ta_samples_reduced.json` | `github.com/splunk/attack_data`, `datasets/suspicious_behaviour/alerts/defender_atp_alerts.log` | Apache-2.0 | Reduced to sourcetype → key paths (`scripts/splunk_ta_samples_spec.py`) |

Not vendored: the SentinelOne 2.1 swagger (`scripts/fetch_swagger.sh` downloads
it into `data/`, which is gitignored). Values in the mock's fixtures are
type-correct defaults or the vendor's documented examples, never a
recording's data.

A reference proves what a real reply carries; a recording never proves what
it does not. Which side counts is set per source in `scripts/schema_drift.py`.
