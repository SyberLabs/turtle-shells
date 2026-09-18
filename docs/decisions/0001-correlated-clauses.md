# ADR-0001: Correlated clauses

## Status

Accepted for P0.

## Context

Independent global lists of actions, resources, and credentials create Cartesian products. “Read A with X” plus “write B with Y” must not become “write A with Y”.

## Decision

Represent each grant as a complete correlated clause. Matching requires the whole tuple. Evaluation never flattens dimensions.

## Consequences

Policies are more verbose. Conservative false negatives are preferred over authority expansion.
