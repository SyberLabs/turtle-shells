# ADR-0002: Conservative one-parent-clause subsumption

## Status

Accepted for P0.

## Context

A child clause might be justified by the union of several parent clauses. Computing that union safely is easy to get wrong.

## Decision

A child clause is valid only if one complete parent clause conservatively subsumes it. If a child would need multiple parents, reject it (`E_DELEGATION_WIDENS`).

## Consequences

Some legitimate narrowing is rejected. Authority expansion is not.
