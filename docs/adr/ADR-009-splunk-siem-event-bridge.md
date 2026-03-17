# ADR-010: Splunk SIEM Event Bridge Architecture

## Status

Accepted

## Context

MockDR supports five EDR vendors (SentinelOne, CrowdStrike, Microsoft Defender, Elastic Security, Cortex XDR). Adding Splunk as vendor #6 creates a unique requirement: Splunk is not an EDR but a SIEM that aggregates events from all five EDR vendors. The mock must automatically bridge EDR events into the Splunk event store with the correct sourcetypes, indexes, and field schemas that match the real Splunk add-ons.

The key question is: **how should EDR events propagate to the Splunk mock?**

Options considered:

1. **External message queue** (Redis, RabbitMQ) — rejected: adds external dependency, violates MockDR's zero-dependency philosophy
2. **Webhook-based forwarding** (EDR mocks POST to Splunk HEC) — rejected: adds network overhead, creates circular dependency, harder to test
3. **Separate background process** — rejected: adds process management complexity, eventual consistency issues
4. **In-process event bus** — selected: zero latency, no external deps, synchronous delivery, easily testable

## Decision

Use an in-process publish/subscribe event bus (`domain/event_bus.py`) with synchronous delivery:

- EDR application layer commands publish `DomainEvent` instances after mutations
- The Splunk event bridge subscribes to these events and creates formatted Splunk events
- Events are transformed to match the exact sourcetype and field schema of the real Splunk add-ons
- High-severity events additionally generate ES notable events in the `notable` index

The event bus is a module-level singleton. Subscribers are registered at application startup. All delivery is synchronous — after an EDR command returns, the corresponding Splunk event already exists.

## Consequences

### Positive

- **Zero latency**: Splunk events exist immediately after EDR mutations — no polling, no eventual consistency
- **Zero dependencies**: No message broker, no network calls, no background workers
- **Deterministic**: Same seed data always produces the same Splunk events
- **Testable**: Unit tests can subscribe to the bus and verify events without network mocking
- **Simple**: ~150 LOC for the entire event bus implementation

### Negative

- **Tight coupling**: EDR commands must know about the event bus (mitigated: publishing is optional, bus is a thin abstraction)
- **No persistence**: Events are lost on restart (acceptable for a mock — seed data is replayed)
- **Single-process only**: Cannot scale to multiple processes (not a requirement for MockDR)

### Neutral

- Event bridge formatters must be maintained when EDR mock schemas change
- Seed data replay through the bridge creates a realistic event backlog on startup
