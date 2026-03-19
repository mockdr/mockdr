# ADR-012: Microsoft Sentinel ARM API Mock Design

## Status

Accepted

## Context

Adding Microsoft Sentinel (vendor #7) requires mocking the Azure Resource Manager (ARM) REST API pattern. Unlike the other mocks which use flat URL structures, Sentinel uses deeply nested ARM resource paths with subscription/resourceGroup/workspace scoping. The mock must also include a Log Analytics KQL query endpoint.

Options considered for path handling:

1. **Strict path validation** — reject requests with wrong subscription/workspace IDs. Rejected: adds complexity, no value for SOAR testing.
2. **Path prefix middleware** — strip the ARM prefix in middleware. Rejected: interferes with other vendor routes.
3. **Accept any workspace, ignore values** — selected: FastAPI path parameters capture the ARM components but the business logic ignores them. Simplest approach that satisfies XSOAR.

## Decision

- Mount all Sentinel routes under `/sentinel` prefix
- ARM workspace path components are accepted as path parameters but ignored
- KQL parser supports the subset XSOAR sends: `SecurityIncident`, `SecurityAlert` tables, `where`, `project`, `sort by`, `take`, `summarize count() by`, `where ... in (...)`, `ago()`
- MDE alerts automatically create Sentinel incidents with `providerName: "Microsoft 365 Defender"` — replicating the real M365 Defender bi-directional sync
- All other EDR vendors create incidents with `providerName: "Azure Sentinel"` via scheduled analytics rules

## Consequences

### Positive
- Full XSOAR Azure Sentinel integration compatibility
- Cross-SIEM correlation: same EDR event appears in both Splunk (as notable) and Sentinel (as incident)
- Entity extraction provides realistic Account/Host/IP entities for SOAR enrichment

### Negative
- ARM path parameters add URL verbosity (~200 chars per request)
- KQL parser is minimal — won't support complex analytics queries
- No support for ARM role-based access control (all authenticated users can do everything)
