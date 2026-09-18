# ADR-0003: Server-side / stateful grants

## Status

Accepted for P0 (in-memory model).

## Context

Offline attenuable tokens complicate revocation and shared-domain accounting. P0 still needs a reservation interface that is safe under concurrent requests.

## Decision

Grants are stateful records compiled from manifests. Shared budgets live in an in-memory mutex-serialized ledger. P0 does not persist SQLite and does not issue bearer grant tokens.

## Consequences

The ledger is process-local. Restart loses simulated reservations. That limitation is explicit: P0 makes no containment or production accounting claim.
