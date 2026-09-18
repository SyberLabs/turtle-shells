# ADR-0004: Fail closed on unsupported semantics

## Status

Accepted for P0.

## Context

Unknown fields, regex predicates, YAML aliases, non-finite numbers, and missing trusted inputs are common bypass paths if treated as “ignore”.

## Decision

Malformed, unknown, unsupported, or missing trusted context fails closed. Adapter validity and approval validity default to unsatisfied. Evaluation errors are denials with stable reason codes, never panics on manifest input.

## Consequences

Authors must be explicit. Convenience defaults that would allow are forbidden.
