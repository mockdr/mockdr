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

Event structure uses `metadata.eventType` + `event.*` fields:
- `DetectionSummaryEvent` — from detections
- `IncidentSummaryEvent` — from incidents

Key fields: `event.ComputerName`, `event.UserName`, `event.DetectName`, `event.Severity`, `event.SeverityName`, `event.FileName`, `event.CommandLine`, `event.SHA256String`

## Microsoft Defender → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `ms:defender:endpoint:alerts` | `msdefender` | `ms:defender:endpoint` | Alert created |
| `ms:defender:endpoint:machines` | `msdefender` | `ms:defender:endpoint` | Machine status change |

Fields mirror the MDE API alert/machine JSON objects.

## Elastic Security → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `elastic:security:alerts` | `elastic_security` | `elastic:security` | Rule alert triggered |
| `elastic:security:endpoints` | `elastic_security` | `elastic:security` | Endpoint status change |

## Cortex XDR → Splunk

| Sourcetype | Index | Source | Trigger |
|------------|-------|--------|---------|
| `pan:xdr:incidents` | `cortex_xdr` | `pan:xdr` | Incident created |
| `pan:xdr:alerts` | `cortex_xdr` | `pan:xdr` | Alert created |
| `pan:xdr:endpoints` | `cortex_xdr` | `pan:xdr` | Endpoint status change |

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
