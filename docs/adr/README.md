# Architecture Decision Records

This directory contains ADRs for the mockdr project.
Each ADR documents a significant design choice: the context that drove it,
the decision made, alternatives considered, and the consequences.

| ADR                                                   | Title                                                                    | Status   |
| ----------------------------------------------------- | ------------------------------------------------------------------------ | -------- |
| [ADR-001](ADR-001-in-memory-store.md)                 | In-Memory Storage with Thread-Safe Singleton Store                       | Accepted |
| [ADR-002](ADR-002-cqrs-application-layer.md)          | CQRS Application Layer                                                   | Accepted |
| [ADR-003](ADR-003-keyset-cursor-pagination.md)        | Keyset Cursor Pagination Matching S1 Wire Format                         | Accepted |
| [ADR-004](ADR-004-internal-field-stripping.md)        | Domain Objects Store Internal Fields; Query Layer Strips Before Response | Accepted |
| [ADR-005](ADR-005-deterministic-seed-data.md)         | Deterministic Seed Data with Fixed RNG and Dependency-Ordered Seeding    | Accepted |
| [ADR-006](ADR-006-recording-proxy-middleware.md)      | Three-Mode Recording Proxy Middleware                                    | Accepted |
| [ADR-007](ADR-007-filtering-system.md)                | Declarative FilterSpec System with Dot-Path Field Access                 | Accepted |
| [ADR-008](ADR-008-domain-dataclasses-not-pydantic.md) | Domain Objects as Python Dataclasses, Not Pydantic Models                | Accepted |
| [ADR-009](ADR-009-splunk-siem-event-bridge.md)        | Splunk SIEM Event Bridge Architecture                                    | Accepted |
| [ADR-010](ADR-010-domain-event-bus.md)                | In-Process Domain Event Bus for Cross-Vendor Bridging                    | Accepted |
| [ADR-011](ADR-011-splunk-rest-api-design.md)          | Splunk REST API Mock Design (Auth + SPL Scope)                           | Accepted |
| [ADR-012](ADR-012-sentinel-arm-api-pattern.md)        | Microsoft Sentinel ARM API Mock Design                                   | Accepted |
| [ADR-013](ADR-013-public-testing-api.md)              | Public Testing API — MockdrClient and mockdr_server Fixture              | Accepted |

## Format

Each ADR follows the structure:

- **Status**: `Proposed` → `Accepted` → `Superseded by ADR-NNN`
- **Context**: Why was this decision needed?
- **Decision**: What was decided?
- **Alternatives Considered**: What else was evaluated and why was it rejected?
- **Consequences**: Positive and negative outcomes of the decision.
