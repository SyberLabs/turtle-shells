# P1 containment notes

P1 adds host-side machinery for a contained worker. It does not make Turtle a production authorization system.

## Claim ceiling

> Local execution containment within tested backend assumptions.

## What P1 does

- Probe the host and refuse admission when Linux, `openat2`, or gVisor `runsc` is missing
- Classify snapshot paths and exclude credential/git directories
- Import/export snapshots with `openat2` on Linux
- Compile a broker-only, unprivileged launch plan from a `TurtlePolicy`
- Authorize typed `inference.generate` with a per-instance binding (no caller-selected URLs or tools)
- Provide `turtle doctor`, `turtle snapshot import`, `turtle export`, and `turtle run`

## What P1 does not do

- Run a sandbox on Windows or any host without `runsc`
- Emit `EnforcementStatus::Enforced`
- Provide MCP, GitHub adapters, OAuth, a credential vault, or `turtled`
- Treat export as a code-safety review

`turtle run` compiles a launch plan, then fails closed through `UnsupportedBackend` until a certified gVisor create/inspect path exists on the host.
