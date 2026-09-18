# P0 evidence report

**Date:** 18 September 2026  
**Host:** Windows 10, rustc 1.98.1 (`x86_64-pc-windows-gnu`), WinLibs GCC 16.1.0  
**Claim ceiling:** Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.

This report records commands actually run in the P0 implementation pass. It does not license sandbox, credential, or production-authorization claims.

## Commands and results

### Format

```
cargo fmt --all --check
```

Result: `fmt_exit=0`.

### Lint (warnings as errors)

```
cargo clippy --workspace --all-targets -- -D warnings
```

Result: `clippy_exit=0`. `Finished dev profile`.

### Complete test suite

```
cargo test --workspace
```

Result: `test_exit=0`.

| Target | Passed | Failed |
|---|---|---|
| turtle-cli `cli.rs` | 4 | 0 |
| turtle-policy lib (`src2` path unit) | 1 | 0 |
| adversarial_cross_product | 3 | 0 |
| adversarial_identity | 1 | 0 |
| attenuation | 7 | 0 |
| budgets | 4 | 0 |
| canonical | 2 | 0 |
| eval_invariants | 6 | 0 |
| fixtures_more | 3 | 0 |
| manifest | 6 | 0 |
| plan | 1 | 0 |
| proptest_digest | 1 | 0 |
| reason_codes | 2 | 0 |
| yaml_strict | 9 | 0 |
| turtle-policy-ref differential | 1 | 0 |
| turtle-policy-ref independence | 1 | 0 |
| turtle-policy-ref properties | 2 | 0 |
| **Total (this run)** | **54** | **0** |

Doc-tests: 0 executed. Binary unittests with no cases: turtle-cli main, turtle-policy-ref lib.

### Concurrency race (20 repeats)

```
cargo test -p turtle-policy --test budgets last_unit_has_exactly_one_winner -- --exact
```

Repeated 20 times. `race_failures=0`.

### CLI smoke

```
cargo run -p turtle-cli --quiet -- policy check tests/fixtures/valid/read-only-repo-worker.yaml
```

Exit 0. Output:

```
digest=4d8a5e1094882c483f5985d164ab08ba331ffd212d0ccc99af67d9cce92e8945
valid TurtlePolicy `rise-worker` with 2 correlated grant clauses
Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.
```

```
cargo run -p turtle-cli --quiet -- policy explain tests/fixtures/valid/read-only-repo-worker.yaml
```

Exit 0. Explanation listed correlated clauses and an enforcement plan whose rows are `status=Unsupported` with `limitation=not deployed in P0`.

```
cargo run -p turtle-cli --quiet -- policy diff --format json tests/fixtures/diff/old.yaml tests/fixtures/diff/widen.yaml
```

Exit 2 (widening detected). JSON reported added write grant, recipients, write path, templates, higher ceilings, and later lifetime.

### Placeholder scan

Workspace search for `TODO|FIXME|unimplemented!|todo!|TBD` outside the plan file and `target/`: no implementation placeholders.

## Documented adaptations

- JSON Schema is shipped at `schemas/turtle-policy-v0alpha1.schema.json`. Runtime validation is a fail-closed YAML frontend plus required-field / unknown-field checks and serde `deny_unknown_fields`. The `jsonschema` crate was not used, so policy evaluation cannot fetch remote schema resources.
- Occupancy fields are parsed and appear in the enforcement plan; they are not reserved by the cumulative budget ledger.
- Property tests include deterministic attenuation/differential cases plus a `proptest` digest case.

## Out of P0 (specified, not implemented)

From design spec sections 4–7, 9, 16, 18, and 19:

- Sandbox/launcher, gVisor, cgroups, `openat2` import/export (P1)
- Broker-only network dataplane, credential vault, OAuth, MCP gateway, provider adapters (P2)
- Daemon Unix socket APIs, SQLite, dispatch permits, approvals UI (P2+)
- Isolated child sandboxes and cascade revocation runtime (P3)
- TLA+ / state-machine model (required before P3)
- `turtle doctor/run/inspect/tree/approvals/revoke/audit/export`
- Occupancy enforcement of memory/CPU/PIDs
- `E_DRIVER_DRIFT`, `E_AUDIT_UNAVAILABLE`, and `E_OUTCOME_UNKNOWN` are stable serialized codes; they are not produced by typical P0 evaluate paths

## What this evidence licenses

P0 may be described as a pure policy evaluator, conservative delegation checker, and simulated in-memory shared-budget ledger with a non-enforcing plan and CLI. It may not be described as a sandbox, credential broker, secure agent runtime, or production-ready authorization system.

## Next smallest milestone

P1 contained worker: Linux sandbox, snapshot filesystem, no raw internet, inference broker, patch output — still a separate implementation pass.
