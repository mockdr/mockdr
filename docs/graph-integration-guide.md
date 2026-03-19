# Microsoft Graph API Integration Guide

## Overview

MockDR includes a comprehensive Microsoft Graph API mock covering Entra ID, Intune, M365 Productivity, and Security — mounted under `/graph`. It implements the Azure AD v2.0 OAuth2 client credentials flow with **plan-based feature gating** that simulates Plan 1, Plan 2, and Defender for Business license tiers.

## Connection Details

| Setting | Value |
|---------|-------|
| Base URL | `http://localhost:8001/graph` |
| v1.0 API | `/graph/v1.0/...` |
| Beta API | `/graph/beta/...` |
| Auth | Azure AD OAuth2 (client credentials) |
| Response Format | OData v4 (`{"@odata.context": "...", "value": [...]}`) |

## OAuth2 Credentials

| Role | Client ID | Client Secret | Plan |
|------|-----------|---------------|------|
| Global Admin | `graph-mock-admin-client` | `graph-mock-admin-secret` | Plan 2 (E5) |
| Security Admin | `graph-mock-security-client` | `graph-mock-security-secret` | Plan 2 (E5) |
| SMB Admin | `graph-mock-smb-client` | `graph-mock-smb-secret` | Defender for Business |
| Plan 1 User | `graph-mock-p1-client` | `graph-mock-p1-secret` | Plan 1 (E3) |
| Intune Admin | `graph-mock-intune-client` | `graph-mock-intune-secret` | Plan 2 (Intune) |
| Mail Only | `graph-mock-mail-client` | `graph-mock-mail-secret` | None (E3) |

## Quick Start

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8001/graph/oauth2/v2.0/token \
  -d "client_id=graph-mock-admin-client&client_secret=graph-mock-admin-secret&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \
  | jq -r .access_token)

# List Entra users
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/graph/v1.0/users?\$select=displayName,userPrincipalName,department&\$top=10"

# List Intune devices
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/graph/v1.0/deviceManagement/managedDevices

# List security alerts
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/graph/v1.0/security/alerts_v2
```

## XSOAR / Demisto Integration Configuration

### Microsoft Graph Security

1. **Server URL**: `http://localhost:8001/graph`
2. **Client ID**: `graph-mock-admin-client`
3. **Client Secret**: `graph-mock-admin-secret`
4. **Tenant ID**: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
5. **Self-Deployed**: Yes
6. **Use a proxy**: No

### Microsoft Graph User

1. **Server URL**: `http://localhost:8001/graph`
2. **Client ID**: `graph-mock-admin-client`
3. **Client Secret**: `graph-mock-admin-secret`
4. **Self-Deployed**: Yes

### Microsoft Graph Device Management (Intune)

1. **Server URL**: `http://localhost:8001/graph`
2. **Client ID**: `graph-mock-intune-client`
3. **Client Secret**: `graph-mock-intune-secret`
4. **Self-Deployed**: Yes

## Plan-Based Feature Gating

Different OAuth clients are associated with different license plans. Endpoints that require a higher plan return HTTP 403 with a Graph-style error:

```json
{
  "error": {
    "code": "Authorization_RequestDenied",
    "message": "This feature requires a higher license tier. Current plan: plan1. Required: plan2.",
    "innerError": { "date": "...", "request-id": "..." }
  }
}
```

### Feature Availability by Plan

| Feature | Plan 1 (E3) | Plan 2 (E5) | Defender for Business |
|---------|-------------|-------------|----------------------|
| Users, Groups, Organization | Yes | Yes | Yes |
| Conditional Access Policies | Yes | Yes | Yes |
| Mail, Files, Teams | Yes | Yes | Yes |
| Subscribed SKUs, Applications | Yes | Yes | Yes |
| Sign-In Logs, Audit Logs | Yes | Yes | Yes |
| Security Alerts & Incidents | **No** | Yes | Yes |
| Advanced Hunting (KQL) | **No** | Yes | **No** |
| Identity Protection (Risky Users) | **No** | Yes | **No** |
| Intune Device Management | **No** | Yes | Yes |
| Attack Simulation | **No** | Yes | **No** |

### Testing Plan Gating

```bash
# Plan 1 token — should get 403 on hunting
P1_TOKEN=$(curl -s -X POST http://localhost:8001/graph/oauth2/v2.0/token \
  -d "client_id=graph-mock-p1-client&client_secret=graph-mock-p1-secret&grant_type=client_credentials" \
  | jq -r .access_token)

# Users: 200 OK (any plan)
curl -H "Authorization: Bearer $P1_TOKEN" http://localhost:8001/graph/v1.0/users

# Advanced Hunting: 403 Forbidden (Plan 2 only)
curl -X POST -H "Authorization: Bearer $P1_TOKEN" -H "Content-Type: application/json" \
  -d '{"Query":"DeviceProcessEvents | take 5"}' \
  http://localhost:8001/graph/v1.0/security/runHuntingQuery

# Identity Protection: 403 Forbidden (Plan 2 only)
curl -H "Authorization: Bearer $P1_TOKEN" \
  http://localhost:8001/graph/v1.0/identityProtection/riskyUsers
```

## OData Query Support

All list endpoints support standard OData query parameters:

| Parameter | Example | Description |
|-----------|---------|-------------|
| `$filter` | `?$filter=severity eq 'high'` | Filter by field values |
| `$select` | `?$select=displayName,id` | Return only specified fields |
| `$top` | `?$top=10` | Page size (max 999) |
| `$skip` | `?$skip=20` | Offset pagination |
| `$orderby` | `?$orderby=createdDateTime desc` | Sort results |
| `$search` | `?$search="displayName:John"` | Full-text search |
| `$count` | `?$count=true` | Include total count (requires `ConsistencyLevel: eventual` header) |

### $count Example

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H "ConsistencyLevel: eventual" \
  "http://localhost:8001/graph/v1.0/deviceManagement/managedDevices?\$count=true&\$top=1"
# Response includes: "@odata.count": 66
```

## API Coverage

### Entra ID

| Endpoint | Method | Path |
|----------|--------|------|
| List users | GET | `/v1.0/users` or `/beta/users` |
| Get user | GET | `/v1.0/users/{id}` |
| User memberships | GET | `/v1.0/users/{id}/memberOf` |
| User mail rules | GET | `/v1.0/users/{id}/mailFolders/inbox/messageRules` |
| List groups | GET | `/v1.0/groups` |
| Group members | GET | `/v1.0/groups/{id}/members` |
| Directory roles | GET | `/v1.0/directoryRoles` |
| Role members | GET | `/v1.0/directoryRoles/{id}/members` |
| CA policies | GET | `/v1.0/identity/conditionalAccess/policies` |
| Named locations | GET | `/v1.0/identity/conditionalAccess/namedLocations` |
| Admin units | GET | `/v1.0/directory/administrativeUnits` |
| MFA registration | GET | `/beta/reports/authenticationMethods/userRegistrationDetails` |
| Service principals | GET | `/v1.0/servicePrincipals` |
| Applications | GET | `/v1.0/applications` |
| Subscribed SKUs | GET | `/v1.0/subscribedSkus` |
| Organization | GET | `/v1.0/organization` |
| Sign-in logs | GET | `/v1.0/auditLogs/signIns` |
| Audit logs | GET | `/v1.0/auditLogs/directoryAudits` |
| Risky users | GET | `/v1.0/identityProtection/riskyUsers` |
| Risk detections | GET | `/v1.0/identityProtection/riskDetections` |

### Intune / Device Management

| Endpoint | Method | Path |
|----------|--------|------|
| Managed devices | GET | `/v1.0/deviceManagement/managedDevices` |
| Get device | GET | `/v1.0/deviceManagement/managedDevices/{id}` |
| Detected apps | GET | `/v1.0/deviceManagement/detectedApps` |
| App devices | GET | `/v1.0/deviceManagement/detectedApps/{id}/managedDevices` |
| Compliance policies | GET | `/v1.0/deviceManagement/deviceCompliancePolicies` |
| Device configurations | GET | `/v1.0/deviceManagement/deviceConfigurations` |
| Autopilot devices | GET | `/v1.0/deviceManagement/windowsAutopilotDeviceIdentities` |
| Autopilot profiles | GET | `/beta/deviceManagement/windowsAutopilotDeploymentProfiles` |
| MAM policies | GET | `/v1.0/deviceAppManagement/managedAppPolicies` |
| Mobile apps | GET | `/v1.0/deviceAppManagement/mobileApps` |
| Update rings | GET | `/beta/deviceManagement/windowsUpdateForBusinessConfigurations` |
| Enrollment configs | GET | `/v1.0/deviceManagement/deviceEnrollmentConfigurations` |
| Device categories | GET | `/v1.0/deviceManagement/deviceCategories` |
| Wipe device | POST | `/v1.0/deviceManagement/managedDevices/{id}/wipe` |
| Retire device | POST | `/v1.0/deviceManagement/managedDevices/{id}/retire` |
| Sync device | POST | `/v1.0/deviceManagement/managedDevices/{id}/syncDevice` |
| Reboot device | POST | `/v1.0/deviceManagement/managedDevices/{id}/rebootNow` |
| Defender scan | POST | `/v1.0/deviceManagement/managedDevices/{id}/windowsDefenderScan` |
| Update signatures | POST | `/v1.0/deviceManagement/managedDevices/{id}/windowsDefenderUpdateSignatures` |

### Security

| Endpoint | Method | Path |
|----------|--------|------|
| Alerts v2 | GET | `/v1.0/security/alerts_v2` |
| Get/patch alert | GET/PATCH | `/v1.0/security/alerts_v2/{id}` |
| Incidents | GET | `/v1.0/security/incidents` |
| Get incident | GET | `/v1.0/security/incidents/{id}` (supports `$expand=alerts`) |
| Advanced hunting | POST | `/v1.0/security/runHuntingQuery` |
| Secure scores | GET | `/v1.0/security/secureScores` |
| TI indicators | GET/POST/DELETE | `/v1.0/security/tiIndicators` |
| Attack simulations | GET | `/v1.0/security/attackSimulation/simulations` |
| Threat assessments | GET/POST | `/v1.0/informationProtection/threatAssessmentRequests` |

### M365 Productivity

| Endpoint | Method | Path |
|----------|--------|------|
| User messages | GET | `/v1.0/users/{id}/messages` |
| Send mail | POST | `/v1.0/users/{id}/sendMail` |
| Mail folders | GET | `/v1.0/users/{id}/mailFolders` |
| User drive | GET | `/v1.0/users/{id}/drive` |
| Drive children | GET | `/v1.0/users/{id}/drive/root/children` |
| SharePoint sites | GET | `/v1.0/sites` |
| Teams | GET | `/v1.0/teams` |
| Channels | GET | `/v1.0/teams/{id}/channels` |
| Channel messages | GET/POST | `/v1.0/teams/{id}/channels/{id}/messages` |
| Service health | GET | `/v1.0/admin/serviceAnnouncement/healthOverviews` |

## Compliance Violation Scenarios

The seed data deliberately includes realistic compliance violations that security tools should detect:

| # | Finding | Details |
|---|---------|---------|
| 1 | Former employee with external mail forwarding | Disabled account still forwarding to `competitor.com` |
| 2 | Former employee with Global Admin role | Disabled user in Global Administrator role |
| 3 | Too many Global Admins | 5 assigned (CIS recommends max 4) |
| 4 | Admin without MFA | Security Administrator without MFA registration |
| 5 | Active users without MFA | ~20% of enabled users lack MFA |
| 6 | App tokens not revoked after offboarding | Disabled users with recent non-interactive sign-ins |
| 7 | Stale enabled accounts | Enabled accounts with no sign-in for 90+ days |
| 8 | Guest/external users | B2B guests from contractor/partner domains |
| 9 | Unverified apps with broad permissions | Apps with `Files.ReadWrite.All` and no verified publisher |
| 10 | EOL operating systems | Windows 8.1, Windows 10 1809, macOS Big Sur devices |
| 11 | BYOD personal devices | Personal mobile devices with noncompliant state |
| 12 | License near-exhaustion | Intune P1 at 96% consumed |
| 13 | CA policy in report-only mode | "Block countries" not enforced |
| 14 | Risky users not remediated | 5 risky users with high/medium risk levels |

## Cross-Vendor Data Consistency

The same 60-device fleet is shared across all eight mock vendors. The same machine "WKSTN-WPGZRI" running "Windows 8.1 Enterprise" appears in:

- SentinelOne (agent)
- CrowdStrike (host)
- MDE (machine)
- Elastic (endpoint)
- Cortex XDR (endpoint)
- Graph (managed device)

The `edr_id_map` store links all vendor-specific IDs for each device. Entra users are derived from MDE machine `loggedOnUsers`, and Graph security alerts are mapped from MDE alerts.
