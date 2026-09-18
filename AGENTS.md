# Turtle contributor notes

Turtle is a versioned authority envelope for autonomous computation.

## Claim ceilings

P0: Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.

P1: Local execution containment within tested backend assumptions.

Do not describe this tree as a sandbox, credential broker, secure agent runtime, or production-ready authorization system unless a certified backend inspection record exists.

## Layout

- `crates/turtle-policy` — trusted semantic core
- `crates/turtle-snapshot` — host-side import/export (`openat2` on Linux)
- `crates/turtle-launcher` — launch plan + fail-closed host probe
- `crates/turtle-broker` — instance-bound inference stub
- `crates/turtle-cli` — owner CLI (`policy`, `doctor`, `snapshot import`, `export`, `run`)
- `tests/reference` — independent evaluator used only for differential tests
- `tests/adversarial` — authority-confusion and identity tests
- `schemas/` — versioned manifest schema
- `docs/decisions/` — architecture decision records
- `docs/evidence/` — reproducible command output

## Invariants

- Fail closed on unknown fields, unsupported constraints, malformed input, and missing trusted context.
- Grant clauses are correlated tuples. Never flatten dimensions into independent global lists.
- `EffectRequest` is not an authority source. Subject and grant come from trusted caller context.
- Adapter validity and approval validity default to unsatisfied.
- No network during policy evaluation. No regex predicates, embedded scripting, or custom cryptography.
- `unsafe` is forbidden except in `crates/turtle-snapshot/src/linux_openat2.rs`.
- Do not emit `EnforcementStatus::Enforced` without backend inspection.
- Uncertified hosts receive `E_UNSUPPORTED_ENFORCEMENT`, not a weaker launch.

## Commands

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
