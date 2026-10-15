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

### Token endpoint URL

Real Entra ID scopes the token endpoint to a tenant —
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`. MockDR accepts
both shapes, so a client built against the real service works unchanged:

```
POST /graph/oauth2/v2.0/token                                          # bare
POST /graph/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/token     # tenant GUID
POST /graph/acmecorp.onmicrosoft.com/oauth2/v2.0/token                 # verified domain
```

Like Entra, the tenant segment accepts either the tenant GUID
(`a1b2c3d4-e5f6-7890-abcd-ef1234567890`) or a verified domain name
(`acmecorp.onmicrosoft.com`), case-insensitively. Any other tenant is rejected
with `400 invalid_request` (AADSTS90002). Set `MOCKDR_STRICT_TENANT=false` to
accept any tenant — useful when pointing a connector that is configured with
your real tenant ID at the mock.

The multi-tenant aliases `common`, `organizations` and `consumers` are rejected
in both modes, because Entra does not support them for client credentials.

The same applies to the `/mde` and `/sentinel` token endpoints, which mock the
same Entra flow against the same tenant.

### Client authentication, scope and discovery

- The secret goes in the form body (`client_secret_post`) or in an
  `Authorization: Basic` header (`client_secret_basic`), both of which Entra
  accepts.
- `scope` must be this API's `/.default` -- `https://graph.microsoft.com/.default`
  here, `https://api.securitycenter.microsoft.com/.default` (or
  `https://api.security.microsoft.com/.default`) on `/mde`. Anything else,
  including another API's resource, is `400 invalid_scope` (AADSTS70011).
- An unknown `client_id` is `400 unauthorized_client` (AADSTS700016); a known
  one with the wrong secret is `401 invalid_client` (AADSTS7000215).
- `GET /graph/{tenant}/v2.0/.well-known/openid-configuration` (and the same on
  `/mde`, `/sentinel`) serves the discovery document MSAL and azure-identity
  read first; its `token_endpoint` points back at the mount. Use
  `https://<mock>/graph/<tenant>` as the authority in MSAL Python
  (`instance_discovery=False`) and `authority="https://<mock>/graph"` with
  `disable_instance_discovery=True` in azure-identity, since both otherwise
  ask login.microsoftonline.com about the host. The document's `jwks_uri`
  serves the key the tokens are signed with (see "The access token" below).
- **The authority must be https.** MSAL Python refuses to build an http one
  ("should consist of an https url") and azure-identity refuses it ("must be
  a TLS protected (https) URL"); msgraph-sdk will not send a token over http
  either, except to localhost. Run the mock with TLS — `uvicorn ...
  --ssl-keyfile mock.key --ssl-certfile mock.crt`, see the README's "TLS,
  which the Azure SDKs insist on" — and have the client trust the
  certificate (`SSL_CERT_FILE` for httpx and aiohttp, `REQUESTS_CA_BUNDLE`
  for requests).

### The access token

The access token is a signed JWT, as Entra's are
([access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)),
so a connector that decodes it -- for `exp`, `tid`, `roles`, `appid` or `oid` --
reads what it would read from Azure. It is a **v1.0** token on all three mounts:
Graph, WindowsDefenderATP, Azure Resource Manager and Log Analytics accept v1.0,
and Entra issues the version the resource asks for whichever endpoint the client
called ([access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens),
"Token ownership").

| Claim | Value |
| --- | --- |
| header | `{"typ": "JWT", "alg": "RS256", "x5t": <kid>, "kid": <kid>}` |
| `aud` | the resource the scope named, `/.default` removed: `https://graph.microsoft.com`, `https://api.securitycenter.microsoft.com` (or whichever Defender identifier was asked for), `https://management.azure.com/`, `https://api.loganalytics.io` |
| `iss`, `idp` | `https://sts.windows.net/{tid}/` (the v1.0 issuer) |
| `iat`, `nbf` | five minutes before issue, as Entra backdates them |
| `exp` | issue time + `expires_in` (3599 on `/graph` and `/mde`, 3600 on `/sentinel`) |
| `appid` | the client ID; `appidacr` is `"1"` (client secret) |
| `idtyp` | `"app"` |
| `oid`, `sub` | the client's service principal: a GUID derived from tenant and client ID, the same in every process and after every reset |
| `roles` | the client's application permissions (below); absent on ARM and Log Analytics tokens |
| `tid` | the client's tenant |
| `uti` | a per-token identifier |
| `ver` | `"1.0"` |

**`roles`.** The seeded clients have no consent record, so their permissions
are derived from what the mock already lets each one do -- its role (who may
write) and, on Graph, its plan (what the feature gates open):

| Mount | Client | `roles` |
| --- | --- | --- |
| `/graph` | every client | `Application.Read.All`, `AuditLog.Read.All`, `Device.Read.All`, `Directory.Read.All`, `Group.Read.All`, `Mail.Read`, `Policy.Read.All`, `User.Read.All` |
| | plan2, defender_for_business | + `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `DeviceManagementManagedDevices.Read.All` |
| | plan2 | + `ThreatHunting.Read.All`, `SecurityEvents.Read.All`, `IdentityRiskyUser.Read.All`, `AttackSimulation.Read.All` |
| | contributor, owner | `ReadWrite` in place of `Read` for mail, alerts, incidents, risky users and managed devices, + `DeviceManagementManagedDevices.PrivilegedOperations.All` where managed devices are open |
| | owner | `ReadWrite.All` for applications, directory, groups and users, + `Policy.ReadWrite.ConditionalAccess` |
| `/mde` | viewer | `AdvancedQuery.Read.All`, `Alert.Read.All`, `File.Read.All`, `Ip.Read.All`, `Machine.Read.All`, `Score.Read.All`, `SecurityRecommendation.Read.All`, `Software.Read.All`, `URL.Read.All`, `User.Read.All`, `Vulnerability.Read.All` |
| | analyst | the viewer's with `Alert.ReadWrite.All`, + `Machine.CollectForensics`, `Machine.Isolate`, `Machine.RestrictExecution`, `Machine.Scan`, `Machine.StopAndQuarantine`, `Ti.ReadWrite.All` |
| | admin | the analyst's with `Machine.ReadWrite.All`, + `Machine.LiveResponse`, `Machine.Offboard` |
| `/sentinel` | any | none: ARM and Log Analytics authorize an application by Azure RBAC |

The names are the APIs' own (the Graph permissions reference; each Defender API
page's Permissions table). The claim describes the client and decides nothing:
the mounts still authorize by the role and plan stored with the token, so
`POST /_dev/graph/plan` changes what a token may do but not the `roles` it was
minted with.

**The signing key** is RSA-2048 in a self-signed certificate, generated when
the process mints its first token and kept until it exits. It is never written
anywhere -- not to `MOCKDR_PERSIST`, not to `/_dev/export`. Its public half is
served at `/{mount}/{tenant}/discovery/v2.0/keys` in Entra's keys-document shape
(`kty`, `use`, `kid`, `x5t`, `n`, `e`, `x5c`, `cloud_instance_name`, `issuer`);
the one key signs for all three mounts.

The token store, not the signature, decides whether a token is accepted, as
before: a correctly signed token the mock never issued is refused, and a token
persisted across a restart is still accepted although it no longer verifies
against the new process's key -- as a token signed with a key Entra has since
rolled would not. Two differences from Azure: Graph's real tokens carry a
`nonce` header that makes them unverifiable outside Graph, and the mock's
verify like any other; and the issuer of the mock's keys document is the mock's
own v2.0 discovery issuer, while the tokens name the v1.0
`https://sts.windows.net/{tid}/` -- the same split Entra's own v2.0 documents
show.

### msgraph-sdk

```python
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient

cred = ClientSecretCredential(
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "graph-mock-admin-client",
    "graph-mock-admin-secret", authority="https://127.0.0.1:8001/graph",
    disable_instance_discovery=True)
client = GraphServiceClient(credentials=cred, scopes=["https://graph.microsoft.com/.default"])
client.request_adapter.base_url = "https://127.0.0.1:8001/graph/v1.0"
```

`PageIterator` follows the mock's `@odata.nextLink`; `runHuntingQuery` takes
the SDK's `RunHuntingQueryPostRequestBody(query=..., timespan=...)`; errors
raise `ODataError` with the status and Graph's error code, as against Graph.

### $count

`$count=true` on directory objects needs the `ConsistencyLevel: eventual`
header, as real Graph does; without it Graph silently ignores the parameter
and so does the mock (no `@odata.count`). Intune's `managedDevices` does not
ignore it: `$count=true` there without the header is
`400 Request_UnsupportedQuery`.

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
    "innerError": { "date": "...", "request-id": "...", "client-request-id": "..." }
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
  -d "scope=https://graph.microsoft.com/.default" \
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
| `$skip` | `?$skip=20` | Offset pagination, where the API documents it (security, Intune, mail). Directory objects (users, groups, applications, service principals, directory roles, administrative units, organization) refuse it with `400 Request_BadRequest` and page by `$skiptoken`, as Graph does |
| `$orderby` | `?$orderby=createdDateTime desc` | Sort results |
| `$search` | `?$search="displayName:John"` | Full-text search. On users and groups it needs the `ConsistencyLevel: eventual` header, or Graph answers `400 Request_UnsupportedQuery` |
| `$count` | `?$count=true` | Include total count. On directory objects it needs `ConsistencyLevel: eventual`; without it the parameter is silently ignored, as Graph documents |

Directory queries that Graph serves only as [advanced queries](https://learn.microsoft.com/en-us/graph/aad-advanced-queries)
-- `$filter` with `endsWith`, `ne` or `not`, and `$filter` with `$orderby` on
users and groups -- need both `ConsistencyLevel: eventual` and `$count=true`;
without them the mock answers `400 Request_UnsupportedQuery` like Graph.

### $count Example

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/graph/oauth2/v2.0/token \
  -d "client_id=graph-mock-admin-client&client_secret=graph-mock-admin-secret&grant_type=client_credentials" \
  -d "scope=https://graph.microsoft.com/.default" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" \
  -H "ConsistencyLevel: eventual" \
  "http://localhost:8001/graph/v1.0/deviceManagement/managedDevices?\$count=true&\$top=1"
# Response includes: "@odata.count": 66
```

### Paging

Follow `@odata.nextLink` verbatim. It is an absolute URL on the host and mount
you called, carrying every query parameter of the original request with only
the page cursor (`$skip` or `$skiptoken`) advanced -- the same contract as
https://learn.microsoft.com/en-us/graph/paging.

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
