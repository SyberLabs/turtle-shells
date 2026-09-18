# Turtle

Turtle is a versioned **authority envelope** for autonomous computation. This repository currently implements **P0: the deterministic semantic kernel**.

## P0 claim ceiling

> Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.

P0 **does**:

- Strictly parse and validate `turtle.syberlabs.space/v0alpha1` manifests
- Represent correlated grant clauses (actions, resources, credentials, recipients, constraints, and obligations stay bound together)
- Evaluate effect requests with default deny, deny precedence, and layer intersection
- Conservatively check parent-to-child attenuation
- Simulate shared-domain cumulative budget reservation under concurrency
- Canonicalize policy JSON (RFC 8785-compatible for the integer JSON subset) and digest it with domain-separated SHA-256
- Emit a machine-readable enforcement **plan** that labels runtime mechanisms as not deployed
- Provide `turtle policy check|explain|diff` and an independent reference evaluator for differential tests

P0 **does not**:

- Sandbox processes, filesystems, or networks
- Broker provider credentials
- Run a daemon, MCP gateway, OAuth flow, or provider adapter
- Enforce memory, CPU, or PID occupancy
- Make a production authorization or containment claim

A valid policy is a reviewed request. It is not an enforced boundary.

## Commands

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p turtle-cli -- policy check tests/fixtures/valid/read-only-repo-worker.yaml
cargo run -p turtle-cli -- policy explain tests/fixtures/valid/read-only-repo-worker.yaml
cargo run -p turtle-cli -- policy diff --format json tests/fixtures/diff/old.yaml tests/fixtures/diff/widen.yaml
```

`policy diff` exits `2` when the new manifest may widen authority.

## Layout

See [AGENTS.md](AGENTS.md). The design specification is [SyberLabs-Turtle-System-Design-Spec-v0.1.md](SyberLabs-Turtle-System-Design-Spec-v0.1.md).

## License

Apache-2.0
