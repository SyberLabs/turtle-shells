# Turtle

Turtle is a versioned **authority envelope** for autonomous computation. This repository implements **P0** (semantic kernel) and **P1** host-side containment machinery.

## Claim ceilings

P0: Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.

P1: Local execution containment within tested backend assumptions.

A valid policy is a reviewed request. `turtle run` on an uncertified host is a refusal, not a sandbox.

P0 **does**:

- Strictly parse and validate `turtle.syberlabs.space/v0alpha1` manifests
- Represent correlated grant clauses (actions, resources, credentials, recipients, constraints, and obligations stay bound together)
- Evaluate effect requests with default deny, deny precedence, and layer intersection
- Conservatively check parent-to-child attenuation
- Simulate shared-domain cumulative budget reservation under concurrency
- Canonicalize policy JSON (RFC 8785-compatible for the integer JSON subset) and digest it with domain-separated SHA-256
- Emit a machine-readable enforcement **plan** that labels runtime mechanisms as not deployed
- Provide `turtle policy check|explain|diff` and an independent reference evaluator for differential tests

P1 **does**:

- Fail closed when Linux, `openat2`, or gVisor `runsc` is missing
- Import/export snapshots on Linux with `openat2`; refuse otherwise
- Compile a broker-only, unprivileged launch plan
- Authorize typed `inference.generate` with a per-instance binding
- Provide `turtle doctor|snapshot import|export|run`

This tree **does not**:

- Sandbox processes on Windows or any host without a certified backend
- Broker provider credentials into the workload
- Run a daemon, MCP gateway, OAuth flow, or provider adapter
- Enforce memory, CPU, or PID occupancy without cgroup attestation
- Make a production authorization claim

See [docs/p1-containment.md](docs/p1-containment.md).

## Commands

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p turtle-cli -- policy check tests/fixtures/valid/read-only-repo-worker.yaml
cargo run -p turtle-cli -- doctor
cargo run -p turtle-cli -- run --manifest tests/fixtures/valid/read-only-repo-worker.yaml
```

`policy diff` exits `2` when the new manifest may widen authority. `doctor` and `run` exit `1` on an uncertified host.

## Layout

See [AGENTS.md](AGENTS.md). The design specification is [SyberLabs-Turtle-System-Design-Spec-v0.1.md](SyberLabs-Turtle-System-Design-Spec-v0.1.md).

## License

Apache-2.0
