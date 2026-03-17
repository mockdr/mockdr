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

## Default Workspace

| Setting | Value |
|---------|-------|
| Subscription ID | `00000000-0000-0000-0000-000000000000` |
| Resource Group | `mockdr-rg` |
| Workspace | `mockdr-workspace` |

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
```

## Example curl Commands

### Get OAuth2 Token
```bash
curl -X POST http://localhost:8001/sentinel/oauth2/v2.0/token \
  -d "client_id=sentinel-mock-client-id&client_secret=sentinel-mock-client-secret&grant_type=client_credentials"
```

### List Incidents
```bash
curl http://localhost:8001/sentinel/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace/providers/Microsoft.SecurityInsights/incidents \
  -H "Authorization: Bearer <token>" \
  -G -d '$top=10'
```

### Run KQL Query
```bash
curl -X POST http://localhost:8001/sentinel/v1/workspaces/mockdr-workspace/query \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"query": "SecurityIncident | take 5"}'
```

### Health Check
```bash
curl http://localhost:8001/sentinel/providers/Microsoft.SecurityInsights/operations
```
