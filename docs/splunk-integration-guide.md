# Splunk Integration Guide

## Overview

MockDR includes a full-fidelity Splunk Enterprise REST API mock that runs on the same port as all other vendors, mounted under the `/splunk` path prefix. It is compatible with the Cortex XSOAR SplunkPy integration.

## Connection Details

| Setting | Value |
|---------|-------|
| Base URL | `http://localhost:8001/splunk` |
| Management API | `/splunk/services/...` |
| HEC | `/splunk/services/collector/...` |
| Auth | Basic Auth or Bearer Token |

## Credentials

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `mockdr-admin` | `admin` |
| `analyst` | `mockdr-analyst` | `sc_admin` |
| `viewer` | `mockdr-viewer` | `user` |

## HEC Tokens

| Token Name | Token Value | Index | Sourcetype |
|------------|-------------|-------|------------|
| `mockdr-edr-sentinelone` | `11111111-1111-1111-1111-111111111111` | `sentinelone` | `sentinelone:channel:threats` |
| `mockdr-edr-crowdstrike` | `22222222-2222-2222-2222-222222222222` | `crowdstrike` | `CrowdStrike:Event:Streams:JSON` |
| `mockdr-edr-general` | `33333333-3333-3333-3333-333333333333` | `main` | (any) |

## Indexes

| Index | Description | Sourcetypes |
|-------|-------------|-------------|
| `sentinelone` | SentinelOne events | `sentinelone:channel:threats`, `sentinelone:channel:agents`, `sentinelone:channel:activities` |
| `crowdstrike` | CrowdStrike events | `CrowdStrike:Event:Streams:JSON` |
| `msdefender` | Microsoft Defender events | `ms:defender:endpoint:alerts`, `ms:defender:endpoint:machines` |
| `elastic_security` | Elastic Security events | `elastic:security:alerts`, `elastic:security:endpoints` |
| `cortex_xdr` | Cortex XDR events | `pan:xdr:incidents`, `pan:xdr:alerts`, `pan:xdr:endpoints` |
| `notable` | ES notable events | `stash` |
| `main` | Default index | (any) |

## XSOAR SplunkPy Configuration

To connect XSOAR SplunkPy to MockDR:

1. **Host**: `localhost` (or Docker hostname)
2. **Port**: `8001`
3. **Username**: `admin`
4. **Password**: `mockdr-admin`
5. **Splunk URL prefix**: `/splunk`
6. **Fetch notable events**: Enabled
7. **Notable macro**: `` `notable` ``

## Supported SPL

The mock SPL parser supports the following patterns:

```spl
search index=<index> sourcetype=<sourcetype> <field>=<value>
| where <field>=<value>
| head <N>
| tail <N>
| table <field1> <field2> ...
| stats count by <field>
| sort [-]<field>
| rename <old> as <new>
| eval <field>=<expr>
`notable`   (macro → search index=notable)
```

Time modifiers: `earliest=-24h`, `latest=now`, `earliest=-7d@d`

## Notable Event Status Values

| Code | Label |
|------|-------|
| `1` | New |
| `2` | In Progress |
| `3` | Pending |
| `4` | Resolved |
| `5` | Closed |

## Example curl Commands

### Login
```bash
curl -X POST http://localhost:8001/splunk/services/auth/login \
  -d "username=admin&password=mockdr-admin&output_mode=json"
```

### Search
```bash
curl -X POST http://localhost:8001/splunk/services/search/jobs \
  -H "Authorization: Basic YWRtaW46bW9ja2RyLWFkbWlu" \
  -H "Content-Type: application/json" \
  -d '{"search": "search index=sentinelone | head 5"}'
```

### Get Results
```bash
curl http://localhost:8001/splunk/services/search/v2/jobs/{sid}/results \
  -H "Authorization: Basic YWRtaW46bW9ja2RyLWFkbWlu"
```

### Submit HEC Event
```bash
curl -X POST http://localhost:8001/splunk/services/collector/event \
  -H "Authorization: Splunk 11111111-1111-1111-1111-111111111111" \
  -d '{"event": {"message": "test"}, "sourcetype": "test", "index": "sentinelone"}'
```

### Update Notable
```bash
curl -X POST http://localhost:8001/splunk/services/notable_update \
  -H "Authorization: Basic YWRtaW46bW9ja2RyLWFkbWlu" \
  -H "Content-Type: application/json" \
  -d '{"ruleUIDs": ["event-id"], "status": "2", "comment": "Investigating"}'
```

### Server Info (Health Check)
```bash
curl http://localhost:8001/splunk/services/server/info?output_mode=json
```
