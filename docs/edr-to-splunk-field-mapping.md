# EDR-to-Splunk Field Mapping

## Overview

MockDR automatically bridges events from all 5 EDR vendors into the Splunk event store using the exact sourcetypes, indexes, and field schemas that the real Splunk add-ons produce.

## SentinelOne → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `sentinelone:channel:threats` | `sentinelone` | `sentinelone:api` | Threat created/updated |
| `sentinelone:channel:agents` | `sentinelone` | `sentinelone:api` | Agent status change |
| `sentinelone:channel:activities` | `sentinelone` | `sentinelone:api` | Activity logged |

The `_raw` field contains the JSON-serialized S1 API response object. Field extraction follows the SentinelOne App for Splunk (splunkbase.splunk.com/app/5433).

## CrowdStrike → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `CrowdStrike:Event:Streams:JSON` | `crowdstrike` | `CrowdStrike:Event:Streams` | Detection/Incident events |

Event structure uses `metadata.eventType` + `event.*` fields, as recorded from the Falcon Event Streams API (`data/vendor-specs/cs_event_streams_reduced.json`):
- `EppDetectionSummaryEvent` — from detections (`DetectionSummaryEvent` is the legacy type)
- `IncidentSummaryEvent` — from incidents, exactly nine fields

Key fields: `event.Hostname`, `event.UserName`, `event.Name`, `event.Severity` (10–100), `event.SeverityName`, `event.FileName`, `event.CommandLine`, `event.SHA256String`

## Microsoft Defender → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `ms:defender:atp:alerts` | `msdefender` | `ms:defender` | Alert created |
| `ms:defender:machines` | `msdefender` | `ms:defender` | Machine status change |

Sourcetypes and events follow the Splunk Add-on for Microsoft Security: each event is the `/api/alerts` (evidence expanded) or `/api/machines` object as the API serves it. Reference: `data/vendor-specs/splunk_ta_samples_reduced.json` (recorded add-on events from `splunk/attack_data`).

## Elastic Security → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `elastic:security:alerts` | `elastic_security` | `elastic:security` | Rule alert triggered |
| `elastic:security:endpoints` | `elastic_security` | `elastic:security` | Endpoint status change |

## Cortex XDR → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `pan:xdr:incident` | `cortex_xdr` | `pan:xdr` | Incident created |
| `pan:xdr:alert` | `cortex_xdr` | `pan:xdr` | Alert created |
| `pan:xdr:endpoint` | `cortex_xdr` | `pan:xdr` | Endpoint status change |

Sourcetypes follow the Splunk Add-on for Palo Alto Networks; each event is the object `incidents/get_incidents` / `endpoints/get_endpoint` lists. The add-on reads alerts with `get_alerts_multi_events`, which has no public recording — the alert object recorded under `get_incident_extra_data` stands in.

## Notable Event Generation

High-severity EDR events generate ES notable events in `index=notable`:

| EDR Source | Severity Threshold | Notable Rule Name |
|------------|-------------------|-------------------|
| SentinelOne | confidence ≥ suspicious | `SentinelOne - Threat Detected` |
| CrowdStrike | severity ≥ 3 | `CrowdStrike - Detection Alert` |
| Microsoft Defender | severity ≥ medium | `Microsoft Defender - Endpoint Alert` |
| Elastic Security | all alerts | `Elastic Security - Detection Rule Alert` |
| Cortex XDR | all incidents | `Cortex XDR - Incident Created` |

Each notable includes all fields required by XSOAR SplunkPy: `event_id`, `rule_name`, `rule_title`, `security_domain`, `severity`, `urgency`, `status`, `status_label`, `owner`, `src`, `dest`, `user`, `description`, `drilldown_search`, `time`, `_time`, `info_min_time`, `info_max_time`.
