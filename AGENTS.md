# Turtle contributor notes

Turtle is a versioned authority envelope for autonomous computation.

## P0 claim ceiling

Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.

Do not describe this tree as a sandbox, credential broker, secure agent runtime, or production-ready authorization system.

## Layout

- `crates/turtle-policy` — trusted semantic core
- `crates/turtle-cli` — owner CLI (`policy check|explain|diff`)
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
- No `unsafe`, no network during evaluation, no regex predicates, no embedded scripting, no custom cryptography.

## Commands

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
