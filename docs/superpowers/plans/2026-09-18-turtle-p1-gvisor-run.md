# Turtle P1 gVisor run + live T04/T05/T07

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `turtle run` create a frozen gVisor sandbox, inspect it against the launch plan, and start it only on a certified host; prove T04/T05/T07 with config tests everywhere and live `runsc` tests on Linux CI.

**Architecture:** Compile an OCI runtime spec from `LaunchPlan`. P1 uses gVisor `--network=none` plus an optional unix broker socket mount. That is stricter than a veth-to-broker dataplane: there is no IP route to the host, metadata, or the public internet. `inspect_oci` rejects host network, docker/SSH/browser sockets, inherited secrets, and host `/proc` binds. `GvisorBackend::create_frozen` writes the bundle, inspects, then `runsc create` without start. Live tests start the container, run an in-guest probe, and assert a host TCP canary received zero connections.

**Tech Stack:** Existing workspace. Pin gVisor `release-20260817.0`. Busybox-static in CI for the guest probe. No Docker SDK. No Landlock backend.

## Global Constraints

- Uncertified hosts still get `E_UNSUPPORTED_ENFORCEMENT`.
- Do not emit `EnforcementStatus::Enforced` without an inspection record on the launcher inspection type (policy-crate plans stay unsupported).
- Live network tests must include a host-side observer (canary listener). Guest “connection refused” after a packet is sent is a failed test; `network=none` must yield zero canary accepts.
- Pin runsc. Do not use `latest`.
- `unsafe` remains isolated to `linux_openat2.rs`.

## Files

- Create: `crates/turtle-launcher/src/oci.rs`
- Create: `crates/turtle-launcher/src/gvisor.rs`
- Create: `crates/turtle-launcher/tests/oci.rs`
- Create: `crates/turtle-launcher/tests/live_t04.rs`
- Create: `tests/fixtures/runtime/t04-t05-t07.sh`
- Modify: `crates/turtle-launcher/src/backend.rs`, `lib.rs`, `Cargo.toml`
- Modify: `crates/turtle-cli/src/main.rs`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/decisions/0008-network-none-broker-socket.md`
- Modify: `docs/evidence/p1-contained-worker.md`

## Interfaces

```rust
pub const RUNSC_RELEASE: &str = "release-20260817.0";

pub struct SandboxRequest<'a> {
    pub plan: &'a LaunchPlan,
    pub bundle_dir: &'a Path,
    pub rootfs: &'a Path,
}

pub struct Inspection {
    pub host_network: bool,
    pub has_network_namespace: bool,
    pub network_none: bool,
    pub forbidden_mounts: Vec<String>,
    pub forbidden_env: Vec<String>,
    pub no_new_privs: bool,
}

pub fn write_oci_bundle(req: &SandboxRequest<'_>) -> Result<serde_json::Value, PolicyError>;
pub fn inspect_oci(config: &serde_json::Value) -> Result<Inspection, PolicyError>;

pub struct GvisorBackend;
impl SandboxBackend for GvisorBackend { /* create_frozen writes, inspects, runsc create */ }
pub fn select_backend() -> Box<dyn SandboxBackend>;
```

`create_frozen` on `UnsupportedBackend` still errors. `GvisorBackend` errors unless `probe_host().certified`.

---

### Task 1: OCI spec + inspect (T04/T05/T07 config)

- [ ] Failing tests in `tests/oci.rs`: worker plan bundle has network namespace, `org.syberlabs.turtle.network=none`, no docker.sock mount, no `SSH_AUTH_SOCK`/`DOCKER_HOST`/`GITHUB_TOKEN`/`AWS_SECRET_ACCESS_KEY`, `noNewPrivileges`, not privileged, proc mount type is `proc` not a host bind.
- [ ] Implement `write_oci_bundle` / `inspect_oci`. `inspect_oci` returns `Err` if any hole exists.
- [ ] `cargo test -p turtle-launcher --test oci`
- [ ] Commit `feat: inspect OCI bundles for broker-only and socket isolation`

### Task 2: GvisorBackend frozen create

- [ ] Test: `GvisorBackend.create_frozen` on this host returns `E_UNSUPPORTED_ENFORCEMENT`.
- [ ] Test: `select_backend()` is unsupported when `!probe.certified`.
- [ ] Implement `gvisor.rs`: write bundle, inspect, if certified invoke `runsc --network=none --platform=ptrace create --bundle ...`.
- [ ] Commit `feat: create frozen gVisor sandboxes after plan inspection`

### Task 3: Live T04/T05/T07

- [ ] Fixture script tries wget to `1.1.1.1`, `169.254.169.254`, `10.0.0.1`, `127.0.0.1:$CANARY`; fails the guest if any succeed; fails if docker.sock or `SSH_AUTH_SOCK` present.
- [ ] Host canary binds `0.0.0.0:$port` and counts accepts.
- [ ] `#[ignore]` unless `TURTLE_LIVE_SANDBOX=1` and `runsc` exists. Start frozen sandbox, wait, assert guest exit 0 and canary accepts == 0.
- [ ] CI job installs pinned runsc + busybox-static and runs the ignored test with sudo as required.
- [ ] Commit `test: live T04 T05 T07 against gVisor network-none`

### Task 4: CLI run + docs

- [ ] `turtle run --manifest --rootfs --bundle` uses `select_backend()`. Missing rootfs on a certified host is `E_UNSUPPORTED_ENFORCEMENT` (image not materialized). Uncertified tests unchanged.
- [ ] ADR 0008. Evidence update.
- [ ] Commit `feat: wire turtle run to the certified gVisor backend`
