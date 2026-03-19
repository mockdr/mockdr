# ADR-010: In-Process Domain Event Bus for Cross-Vendor Bridging

**Status**: Accepted

## Context

mockdr simulates seven independent security platforms that, in production environments, are connected via SIEM/SOAR integrations. When a threat is created in SentinelOne, it should appear as a notable event in Splunk and an incident in Microsoft Sentinel — mirroring the real-world event flow that SOAR playbooks depend on.

The challenge is enabling cross-vendor data flow without introducing coupling between vendor modules. The SentinelOne command layer should not import from the Splunk or Sentinel command layers.

## Decision

Implement a thin, synchronous, in-process publish/subscribe event bus (`domain/event_bus.py`) with:

- **Typed domain events** — each vendor defines concrete event dataclasses (`ThreatCreated`, `CsDetectionCreated`, `MdeAlertCreated`, etc.) that extend a base `DomainEvent`.
- **String-keyed subscriptions** — subscribers register for event types by string key, keeping the subscriber list decoupled from the event class hierarchy.
- **Synchronous delivery** — `publish()` calls all handlers inline. No async queue, no background thread. This keeps the system deterministic for testing.
- **Error isolation** — each handler is wrapped in a try/except so one failing subscriber cannot break the publishing command.
- **Thread-safe registration** — a threading lock protects the subscriber list, supporting the playbook executor's background thread.
- **Bridge modules** — `application/splunk/commands/edr_bridge.py` and `application/sentinel/commands/edr_bridge.py` subscribe to all vendor events and create the corresponding Splunk events / Sentinel incidents.

## Alternatives Considered

1. **Direct imports** — Splunk/Sentinel seeders call vendor-specific command layers directly. Rejected: creates circular dependencies and tight coupling.
2. **Async task queue (Celery/Dramatiq)** — overkill for an in-memory mock server. Adds infrastructure complexity with no benefit.
3. **Webhook-based internal events** — self-posting HTTP requests. Rejected: slow, fragile, hard to test deterministically.

## Consequences

**Positive:**
- Zero coupling between vendor modules — adding a new vendor subscriber requires no changes to existing command handlers.
- Deterministic: synchronous delivery means test assertions can check Splunk/Sentinel state immediately after an S1 command.
- The `event_bus.clear()` method makes test teardown trivial.

**Negative:**
- Synchronous delivery means a slow subscriber blocks the HTTP response. Acceptable for a mock server.
- The event bus is a module-level singleton, which complicates unit testing of individual handlers (mitigated by `clear()` + re-subscribe in fixtures).
