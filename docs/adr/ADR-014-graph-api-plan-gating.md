# ADR-014: Microsoft Graph API Mock with Plan-Based Feature Gating

**Status**: Accepted

## Context

MockDR needed a Microsoft Graph API mock that covers the full SMB surface: Entra ID, Intune, M365 Productivity (Mail, Files, Teams), and Security. Unlike the other seven mocked vendors which have a single auth tier, the real Microsoft Graph API gates features based on the tenant's license plan — Plan 1, Plan 2, and Defender for Business each unlock different API endpoints.

The mock must be useful for testing both the happy path (full Plan 2 access) and the error path (Plan 1 user hitting a 403 on advanced hunting). External tools like XSOAR integrations and compliance platforms rely on specific Graph endpoints and must receive the exact OData response format.

## Decision

### 1. Token-Embedded Plan Attribute

Each Graph OAuth client registration carries a `plan` field (`plan1`, `plan2`, `defender_for_business`, `none`) and a `licenses` list. When a token is issued via `POST /graph/oauth2/v2.0/token`, the plan and licenses are stored in the token record. Every subsequent request carries this context.

### 2. Dependency-Factory Feature Gate

A `require_graph_feature(feature_key)` function acts as a FastAPI dependency factory. Routers declare which feature they need:

```python
@router.get("/v1.0/security/runHuntingQuery")
async def run_query(_: dict = Depends(require_graph_feature("security/runHuntingQuery"))):
    ...
```

The dependency checks the token's plan against a static `FEATURE_GATES` dict. Ungated endpoints (users, groups, mail) use the simpler `require_graph_auth` dependency.

### 3. Separate OData Module

The Graph API uses richer OData than MDE — lambda expressions, nested property paths, `$count` with `ConsistencyLevel` header, `$search`. Rather than modifying the battle-tested `mde_odata.py`, a new `graph_odata.py` wraps it and adds Graph-specific pre-processing.

### 4. Same-Fleet Cross-Vendor Seeding

Graph entities are seeded from the same 60-agent fleet as all other vendors via `edr_id_map`. Graph managed devices map 1:1 from S1 agents, Entra users are derived from MDE `loggedOnUsers`, and Graph security alerts transform from MDE alerts. This ensures the same machine shows consistent data across all eight vendor views.

### 5. Deliberate Compliance Violations

The seed data includes intentional compliance gaps (former employees with admin roles, external mail forwarding on disabled accounts, EOL operating systems, unverified apps with broad permissions) so that security tools have actionable findings to detect.

## Alternatives Considered

### A. Runtime Adapter Layer (rejected)

Instead of independent Graph store records seeded from the same fleet, we considered a runtime adapter that transforms MDE/S1 records on-the-fly into Graph format. Rejected because: (a) Graph entities like CA policies, groups, and licenses have no MDE equivalent, (b) mutations to Graph entities shouldn't affect MDE state, (c) adapter complexity would increase coupling.

### B. Modify `mde_odata.py` for Graph Extensions (rejected)

Adding lambda/`$search`/`$count` directly to the MDE parser risked breaking the 380-line module that 11 MDE routers depend on. Wrapping via `graph_odata.py` isolates the risk.

### C. Single Token for All Plans (rejected)

Using a single admin token and ignoring plan gating would make the mock simpler but useless for testing license-tier error handling — a critical path for SMB-focused tools.

## Consequences

### Positive

- Tools can test Plan 1 → Plan 2 upgrade paths by switching OAuth clients
- The same device fleet is consistent across all eight vendor views
- Compliance violations are realistic and detectable by standard auditing tools
- OData extensions don't risk regressions in existing MDE tests

### Negative

- 50+ new store collections increase memory footprint (~2-3 MB)
- 28 seeder files add ~15 seconds to cold-start seed time
- Graph router count (24 modules) is the largest of any vendor, increasing maintenance surface
