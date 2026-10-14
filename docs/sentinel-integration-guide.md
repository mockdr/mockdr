# Microsoft Sentinel Integration Guide

## Overview

MockDR includes a full-fidelity Microsoft Sentinel SIEM mock that runs on the same port, mounted under `/sentinel`. It uses the Azure Resource Manager (ARM) REST API pattern with OAuth2 authentication and includes a Log Analytics KQL query endpoint.

## Connection Details

| Setting | Value |
|---------|-------|
| Base URL | `http://localhost:8001/sentinel` |
| ARM API | `/sentinel/subscriptions/{sub}/resourceGroups/{rg}/.../Microsoft.SecurityInsights/...` |
| Log Analytics | `/sentinel/v1/workspaces/{workspaceId}/query` |
| Auth | Azure AD OAuth2 (client credentials) |

## OAuth2 Credentials

| Setting | Value |
|---------|-------|
| Client ID | `sentinel-mock-client-id` |
| Client Secret | `sentinel-mock-client-secret` |
| Token Endpoint | `POST /sentinel/oauth2/v2.0/token` |
| Tenant-scoped form | `POST /sentinel/{tenant}/oauth2/v2.0/token` |

Real Entra ID scopes the token endpoint to a tenant
(`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`); both shapes
work here, so a client built against the real service needs no special-casing.
The tenant segment takes the mock tenant's GUID
(`a1b2c3d4-e5f6-7890-abcd-ef1234567890`) or its verified domain
(`acmecorp.onmicrosoft.com`); see the
[Graph integration guide](graph-integration-guide.md) for the validation rules
and `MOCKDR_STRICT_TENANT`.

## api-version

Every management-plane request needs `?api-version=`, as Azure Resource Manager
requires. A missing parameter is answered with `400 MissingApiVersionParameter`
and an implausible one (`v1`, `2024`, a pre-2019 date) with
`400 InvalidApiVersionParameter`; any well-formed version from 2019 onwards is
served, `-preview` included. The Log Analytics query endpoint
(`/sentinel/v1/workspaces/{id}/query`) belongs to api.loganalytics.io, not ARM,
and takes no api-version.

## Default Workspace

| Setting | Value |
|---------|-------|
| Subscription ID | `00000000-0000-0000-0000-000000000000` |
| Resource Group | `mockdr-rg` |
| Workspace | `mockdr-workspace` |

## Azure SDKs (azure-mgmt-securityinsight, azure-monitor-query)

The mount is an Entra authority: `/sentinel/{tenant}/v2.0/.well-known/openid-configuration`
is served, so azure-identity's `ClientSecretCredential` works against it. The
Azure SDKs require **https** — azure-identity refuses an http authority and
azure-core will not send a bearer token over http — so run the mock with TLS
(README, "TLS, which the Azure SDKs insist on") and trust its certificate
(`REQUESTS_CA_BUNDLE`).

```python
from datetime import timedelta
from azure.identity import ClientSecretCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.monitor.query import LogsQueryClient

MOCK = "https://127.0.0.1:8001/sentinel"
cred = ClientSecretCredential(
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "sentinel-mock-client-id",
    "sentinel-mock-client-secret", authority=MOCK, disable_instance_discovery=True)

si = SecurityInsights(cred, "00000000-0000-0000-0000-000000000000", base_url=MOCK,
                      credential_scopes=["https://management.azure.com/.default"])
for page in si.incidents.list("mockdr-rg", "mockdr-workspace", top=50).by_page():
    ...

logs = LogsQueryClient(cred, endpoint=MOCK, audience="https://api.loganalytics.io")
logs.query_workspace("mockdr-workspace", "SecurityIncident | take 5",
                     timespan=timedelta(days=1))
```

- `credential_scopes` and `audience` keep the token's scope the real
  resource's; the defaults would derive it from the mock's URL, and the token
  endpoint refuses that scope (`invalid_scope`).
- Give `LogsQueryClient` the mount, **not** `.../sentinel/v1`: azure-monitor-query
  treats an endpoint ending in `/v1` as "host plus API version" and drops
  the whole path, `/sentinel` included.
- `timespan` is applied, as Log Analytics applies it, on top of the query's
  own time filters.

## XSOAR Azure Sentinel Configuration

1. **Azure Cloud**: Custom
2. **Server URL**: `http://localhost:8001/sentinel`
3. **Client ID**: `sentinel-mock-client-id`
4. **Client Secret**: `sentinel-mock-client-secret`
5. **Subscription ID**: `00000000-0000-0000-0000-000000000000`
6. **Resource Group**: `mockdr-rg`
7. **Workspace Name**: `mockdr-workspace`

## Supported Endpoints

### Incidents
- `GET .../incidents` — List with `$filter`, `$orderby`, `$top`, `$skipToken`
- `GET/PUT/DELETE .../incidents/{id}` — CRUD
- `POST .../incidents/{id}/alerts` — List alerts
- `POST .../incidents/{id}/entities` — List entities
- `GET/PUT/DELETE .../incidents/{id}/comments/{id}` — Comments
- `POST .../incidents/{id}/runPlaybook` — Trigger playbook

### Watchlists
- Full CRUD on watchlists and watchlist items

### Threat Intelligence
- Indicators CRUD, query, metrics, tag management

### Analytics Rules
- CRUD for Scheduled, Fusion, MicrosoftSecurityIncidentCreation rules

### Log Analytics (KQL)
Supported patterns:
```kql
SecurityIncident | where Status == "New" | take 50
SecurityAlert | where Severity in ("High", "Medium")
SecurityIncident | summarize count() by Severity
SecurityIncident | project Title, Severity, Status | sort by CreatedTime desc
SentinelOne_CL | summarize max(TimeGenerated)
```

The four custom tables the workspace's data connectors advertise —
`SentinelOne_CL`, `CrowdStrikeFalcon_CL`, `ElasticSecurity_CL`,
`PaloAltoCortexXDR_CL` — answer the events the same install has ingested
from those products, each row carrying the `TimeGenerated` a workspace
orders custom logs by.

## Example curl Commands

### Get OAuth2 Token
```bash
TOKEN=$(curl -s -X POST http://localhost:8001/sentinel/oauth2/v2.0/token \
  -d "client_id=sentinel-mock-client-id&client_secret=sentinel-mock-client-secret&grant_type=client_credentials" \
  --data-urlencode "scope=https://management.azure.com/.default" \
  | jq -r .access_token)
```

A token is for the resource its `scope` names, and each API takes only its
own, as Azure does: the ARM routes want
`https://management.azure.com/.default` (or `https://management.core.windows.net/.default`),
the Log Analytics query wants `https://api.loganalytics.io/.default`. A token
for the other one is refused with `InvalidAuthenticationTokenAudience` — 401
from ARM, 403 from the query API.

### List Incidents
With the management token from above:

<!-- doc-examples: continue -->
```bash
curl http://localhost:8001/sentinel/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace/providers/Microsoft.SecurityInsights/incidents \
  -H "Authorization: Bearer $TOKEN" \
  -G -d 'api-version=2024-03-01' -d '$top=10'
```

### Run KQL Query
The query endpoint takes a token for Log Analytics, not the management one:

```bash
LA_TOKEN=$(curl -s -X POST http://localhost:8001/sentinel/oauth2/v2.0/token \
  -d "client_id=sentinel-mock-client-id&client_secret=sentinel-mock-client-secret&grant_type=client_credentials" \
  --data-urlencode "scope=https://api.loganalytics.io/.default" \
  | jq -r .access_token)

curl -X POST http://localhost:8001/sentinel/v1/workspaces/mockdr-workspace/query \
  -H "Authorization: Bearer $LA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "SecurityIncident | take 5"}'
```

### Health Check
```bash
curl "http://localhost:8001/sentinel/providers/Microsoft.SecurityInsights/operations?api-version=2024-03-01"
```
