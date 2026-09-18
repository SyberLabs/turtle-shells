# ADR-0005: Independent reference evaluator

## Status

Accepted for P0.

## Context

A single decision function can encode the same bug in production and tests.

## Decision

`tests/reference/turtle-policy-ref` reimplements the eligibility formula. It may use production types and parsing. It must not call `turtle_policy::evaluate` or `evaluate_layers`. Differential tests compare allow/deny and reason codes.

## Consequences

Two implementations can drift in explanation text. Codes and eligibility must agree on supported cases. Independence here is separate code paths, not a formal proof.
