# Turtle P1 Contained Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Turtle P1 host-side containment machinery: fail-closed backend probing, safe snapshot import/export, a gVisor launch-plan compiler, a broker-only inference stub, and CLI `doctor|snapshot import|export|run` — without claiming containment on an uncertified host.

**Architecture:** P0 remains the semantic kernel and never claims enforcement. P1 adds three small crates (`turtle-snapshot`, `turtle-launcher`, `turtle-broker`) plus CLI commands. Admission compiles a policy into a `LaunchPlan`, then asks a `SandboxBackend` to create a frozen sandbox and inspect it. The only certified backend is Linux OCI through gVisor `runsc`. If `openat2`, user namespaces, or `runsc` are missing, admission returns `E_UNSUPPORTED_ENFORCEMENT`. Windows, WSL-absent developer hosts, and any userspace “fake sandbox” are not backends.

**Tech Stack:** Rust 1.98.1, existing workspace pins, `libc = 0.2.180` (Linux syscalls only), `sha2`, `serde_json`, `clap`. No HTTP framework: the inference stub is `std::net` + a bounded JSON body. No Docker SDK. No Landlock-as-certified-backend.

## Inspection findings

- P0 is on `main` at https://github.com/SyberLabs/turtle-shells (`11c5ded`).
- This development host is Windows 10. `wsl --install` is not present. Docker is not installed. gVisor cannot run here.
- Spec §8.2: Linux OCI sandbox through gVisor `runsc`. Spec §10.3: fail if `openat2` is unavailable. Spec §20: an unsupported host receives an actionable failure, not a best-effort security badge. Spec §3.2 P1 claim ceiling: “Local execution containment within tested backend assumptions.”
- Therefore P1 on this host is the fail-closed control plane plus Linux-gated implementation. Live T04/T05/T07 sandbox tests run only on Linux CI or a later certified host. They must not be marked passed from Windows unit tests.

## Global Constraints

- Do not describe P1 as production-ready authorization, a credential broker, or a complete Turtle System.
- Do not emit `EnforcementStatus::Enforced` unless a backend inspection record exists for that requirement.
- Do not implement a Windows or “std::process” sandbox to make tests pass.
- Do not grant raw internet, CONNECT proxy, MCP gateway, GitHub adapter, OAuth, or daemon SQLite in this phase (those are P2).
- Snapshot import copies owner-selected regular files into a new tree; it never bind-mounts the live checkout.
- Inference stub rejects caller-selected base URLs, provider-hosted tools, uploads, and background jobs.
- Provider secrets never enter the workload environment, files, argv, or stdout.
- `unsafe` is allowed only in `crates/turtle-snapshot/src/linux_openat2.rs`, documented, and reviewed.
- Pin dependencies with `=` in workspace `Cargo.toml`.
- P0 tests must remain green. P1 does not weaken P0 invariants.

## Spec conflicts and documented adaptations

| Spec / brief point | P1 handling |
|---|---|
| gVisor `runsc` live launch | Implemented as the only `SandboxBackend`. This Windows host cannot run it. `turtle run` fails closed here. Linux CI compiles the backend and runs snapshot `openat2` tests; live `runsc` tests are skipped unless `TURTLE_LIVE_SANDBOX=1` and `runsc` is on PATH. |
| `openat2` required for import/export | Production import/export return `E_UNSUPPORTED_ENFORCEMENT` on non-Linux. Portable tests cover path classification only. |
| Occupancy cgroups | Launch plan records requested memory/pids/cpu. Backend inspects cgroup capability; missing support denies admission. No fake occupancy on Windows. |
| MCP gateway / repository adapter | Out of P1. MCP remains unsupported in the enforcement plan. |
| `turtled` + SQLite | Out of P1. Instance state is process-local. |
| P1 claim ceiling | Printed by `doctor`/`run`. Policy crate `CLAIM_CEILING` stays the P0 sentence so policy evaluation never implies containment. |

## Chosen repository / file structure

```
crates/turtle-snapshot/          host-side import/export
  src/lib.rs
  src/error.rs
  src/classify.rs
  src/artifact.rs
  src/linux_openat2.rs           cfg(target_os = "linux"); isolated unsafe
  src/import.rs
  src/export.rs
  tests/classify.rs
  tests/import_fail_closed.rs
  tests/linux_import.rs          cfg linux
crates/turtle-launcher/
  src/lib.rs
  src/backend.rs
  src/plan.rs
  src/doctor.rs
  src/gvisor.rs
  tests/plan.rs
  tests/doctor.rs
crates/turtle-broker/
  src/lib.rs
  src/identity.rs
  src/inference.rs
  src/server.rs
  tests/identity.rs
  tests/inference.rs
crates/turtle-cli/src/main.rs    add doctor, snapshot, export, run
.github/workflows/ci.yml
docs/decisions/0006-fail-closed-uncertified-host.md
docs/decisions/0007-openat2-import-export.md
docs/evidence/p1-contained-worker.md
```

Public interfaces (names are normative for later tasks):

```rust
// turtle-launcher
pub const P1_CLAIM_CEILING: &str =
    "Local execution containment within tested backend assumptions.";

pub struct HostProbe {
    pub os: &'static str,
    pub openat2: bool,
    pub runsc: Option<String>,
    pub certified: bool,
    pub failures: Vec<String>,
}

pub fn probe_host() -> HostProbe;

pub struct LaunchPlan { /* mounts, network, env allowlist, occupancy, argv, cwd */ }
pub fn compile_launch_plan(policy: &turtle_policy::TurtlePolicy) -> Result<LaunchPlan, turtle_policy::PolicyError>;

pub trait SandboxBackend {
    fn id(&self) -> &'static str;
    fn probe(&self) -> HostProbe;
    fn create_frozen(&self, plan: &LaunchPlan) -> Result<FrozenSandbox, turtle_policy::PolicyError>;
}

pub struct UnsupportedBackend;
pub struct GvisorBackend; // cfg(target_os = "linux")

// turtle-snapshot
pub fn import_snapshot(request: &ImportRequest) -> Result<Snapshot, turtle_policy::PolicyError>;
pub fn export_patch(request: &ExportRequest) -> Result<ExportArtifact, turtle_policy::PolicyError>;

// turtle-broker
pub struct InstanceBinding { pub instance_id: String, pub secret: [u8; 32] }
pub fn mint_instance_binding() -> InstanceBinding;
pub struct InferenceGenerateRequest { pub model: String, pub messages: Vec<InferenceMessage>, pub max_output_tokens: u32 }
pub fn authorize_inference(binding: &InstanceBinding, presented: Option<&[u8]>, body: &serde_json::Value) -> Result<InferenceGenerateRequest, turtle_policy::PolicyError>;
```

---

### Task 1: Fail-closed host probe

**Files:**
- Create: `crates/turtle-launcher/Cargo.toml`
- Create: `crates/turtle-launcher/src/lib.rs`
- Create: `crates/turtle-launcher/src/doctor.rs`
- Create: `crates/turtle-launcher/tests/doctor.rs`
- Modify: `Cargo.toml` workspace members and `turtle-launcher` path dep

**Interfaces:**
- Produces: `probe_host() -> HostProbe`, `P1_CLAIM_CEILING`, `UnsupportedBackend`

- [ ] **Step 1: Write the failing test**

```rust
use turtle_launcher::{probe_host, P1_CLAIM_CEILING};

#[test]
fn uncertified_host_is_not_certified() {
    let probe = probe_host();
    if cfg!(not(target_os = "linux")) {
        assert!(!probe.certified);
        assert!(!probe.openat2);
        assert!(probe.runsc.is_none());
        assert!(!probe.failures.is_empty());
    }
    assert!(P1_CLAIM_CEILING.contains("tested backend assumptions"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p turtle-launcher --test doctor uncertified_host_is_not_certified -- --exact`

Expected: compile error, crate missing.

- [ ] **Step 3: Write minimal implementation**

`probe_host` on non-Linux returns `certified: false`, `openat2: false`, failures including `host is not Linux` and `openat2 unavailable`. On Linux, check `libc::SYS_openat2` usability with a documented probe and look up `runsc` on PATH; `certified` is true only when both exist.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p turtle-launcher --test doctor`

Expected: PASS on this Windows host.

- [ ] **Step 5: Commit**

```
git commit -m "feat: fail closed when the host cannot enforce P1 containment"
```

---

### Task 2: Portable snapshot classification

**Files:**
- Create: `crates/turtle-snapshot/Cargo.toml`
- Create: `crates/turtle-snapshot/src/lib.rs`
- Create: `crates/turtle-snapshot/src/classify.rs`
- Create: `crates/turtle-snapshot/tests/classify.rs`

**Interfaces:**
- Produces: `classify_relative_path(&str) -> Result<turtle_policy::RelPath, PolicyError>`
- Produces: `is_excluded_name(name: &str) -> bool` for `.git`, `.ssh`, `.aws`, `.gnupg`, `.docker`, `.netrc`

- [ ] **Step 1: Write the failing test** covering `../secret`, `/etc/passwd`, `src/../etc`, symlink-looking `src` allowed as a relative path string, and excluded names.

- [ ] **Step 2: Run test; expect crate missing / function missing.**

- [ ] **Step 3: Implement using `turtle_policy::RelPath::parse`. Reject any path whose first segment is an excluded name or that contains an excluded segment.**

- [ ] **Step 4: `cargo test -p turtle-snapshot --test classify` PASS**

- [ ] **Step 5: Commit `test: classify snapshot paths and exclude credential directories`**

---

### Task 3: Import and export fail closed without openat2

**Files:**
- Create: `crates/turtle-snapshot/src/import.rs`
- Create: `crates/turtle-snapshot/src/export.rs`
- Create: `crates/turtle-snapshot/src/artifact.rs`
- Create: `crates/turtle-snapshot/tests/import_fail_closed.rs`

**Interfaces:**

```rust
pub struct ImportRequest<'a> {
    pub source_root: &'a Path,
    pub selected: &'a [turtle_policy::RelPath],
    pub dest_root: &'a Path,
}
pub fn import_snapshot(request: &ImportRequest<'_>) -> Result<Snapshot, PolicyError>;

pub struct ExportRequest<'a> {
    pub snapshot_root: &'a Path,
    pub work_root: &'a Path,
    pub export_subtrees: &'a [turtle_policy::RelPath],
}
pub struct ExportArtifact {
    pub policy_digest: Option<String>,
    pub files: Vec<ExportFile>, // rel path, sha256, mode, deleted
}
pub fn export_patch(request: &ExportRequest<'_>) -> Result<ExportArtifact, PolicyError>;
```

- [ ] **Step 1: Test that on non-Linux, `import_snapshot` and `export_patch` return `ReasonCode::EUnsupportedEnforcement` and do not create dest files.**

- [ ] **Step 2: Confirm failure (missing fn or unexpected Ok).**

- [ ] **Step 3: Non-Linux bodies return `PolicyError::unsupported("openat2 unavailable")`. Linux bodies land in Task 4.**

- [ ] **Step 4: PASS on Windows.**

- [ ] **Step 5: Commit `feat: reject snapshot import and export without openat2`**

---

### Task 4: Linux openat2 import/export

**Files:**
- Create: `crates/turtle-snapshot/src/linux_openat2.rs`
- Create: `crates/turtle-snapshot/src/linux.rs`
- Create: `crates/turtle-snapshot/tests/linux_import.rs`
- Modify: `Cargo.toml` add `libc = "=0.2.180"` as workspace dep; turtle-snapshot depends on it only for linux.

**Interfaces:**
- Isolated `unsafe` syscall wrapper `openat2_beneath(dirfd, path) -> Result<OwnedFd>`.
- Safety comment: path is relative, `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`.

- [ ] **Step 1: Linux tests (compile everywhere with `#[cfg(target_os = "linux")]`):**
  - import selected `src/a.txt`, omit unselected `secret.txt`
  - symlink escape is rejected; host sentinel unchanged
  - `.git/config` excluded even if selected
  - export includes modified regular files under `export_subtrees` and omits files outside them
  - executable mode `0o111` in export is rejected for the first worker template

- [ ] **Step 2: On Windows these tests are not compiled. On Linux CI they fail until implemented.**

- [ ] **Step 3: Implement Linux copy of regular files/directories only. Reject symlink, fifo, socket, device, hard-link (`nlink > 1`).**

- [ ] **Step 4: Linux CI PASS. Windows suite still PASS.**

- [ ] **Step 5: Commit `feat: import and export snapshots with openat2 on Linux`**

---

### Task 5: Launch plan compiler

**Files:**
- Create: `crates/turtle-launcher/src/plan.rs`
- Create: `crates/turtle-launcher/tests/plan.rs`

**Interfaces:**

```rust
pub struct MountSpec {
    pub destination: String, // /workspace/repo, /tmp, /home/agent, /run/turtle
    pub source_kind: MountSource, // Snapshot, Scratch, RuntimeImage, WritableCopy
    pub writable: bool,
}
pub struct NetworkPlan {
    pub mode: BrokerOnly,
    pub raw_destinations_forbidden: bool,
    pub allow_dns: bool,    // false
    pub allow_udp: bool,    // false
    pub broker_endpoint: Option<String>,
}
pub struct EnvPlan {
    pub allowlist: BTreeSet<String>, // PATH, HOME, LANG, TZ, TURTLE_BROKER_URL, TURTLE_INSTANCE
    pub inherit_none: bool,
}
pub struct LaunchPlan {
    pub mounts: Vec<MountSpec>,
    pub network: NetworkPlan,
    pub env: EnvPlan,
    pub no_new_privs: bool,
    pub host_network: bool, // must be false
    pub privileged: bool,   // must be false
    pub occupancy: OccupancyPlan,
    pub argv: Vec<String>,
    pub cwd: String,
}
```

- [ ] **Step 1: Tests:** compile the worker fixture; assert `host_network == false`, `privileged == false`, `no_new_privs`, network mode broker-only, writable mounts only for declared subtrees as independent copies, env allowlist excludes `SSH_AUTH_SOCK`, `AWS_SECRET_ACCESS_KEY`, `DOCKER_HOST`, `GITHUB_TOKEN`. Reject `network.mode != broker-only` and any non-empty raw destinations (already a parse error if schema forbids them; still assert at launch compile).

- [ ] **Step 2: Fail (missing compile_launch_plan).**

- [ ] **Step 3: Implement from `TurtlePolicy` getters.**

- [ ] **Step 4: PASS**

- [ ] **Step 5: Commit `feat: compile a gVisor-oriented launch plan from TurtlePolicy`**

---

### Task 6: Inference broker stub

**Files:**
- Create: `crates/turtle-broker/Cargo.toml`
- Create: `crates/turtle-broker/src/lib.rs`
- Create: `crates/turtle-broker/src/identity.rs`
- Create: `crates/turtle-broker/src/inference.rs`
- Create: `crates/turtle-broker/src/server.rs`
- Create: `crates/turtle-broker/tests/identity.rs`
- Create: `crates/turtle-broker/tests/inference.rs`

**Interfaces:**
- Binding: 32 random bytes from `getrandom` (`getrandom = "=0.3.4"`). Caller-supplied instance id header is not sufficient.
- `authorize_inference` rejects JSON keys `baseUrl`, `base_url`, `tools`, `file_ids`, `uploads`, `background`.
- Allows `{ "model": "registry:approved-model", "messages": [{"role":"user","content":"hi"}], "maxOutputTokens": 16 }`.
- Replay of binding on a different instance id fails.
- Server listens on 127.0.0.1:0, checks `Authorization: Turtle <hex>`.

- [ ] **Step 1: Write tests for rejection of alternate endpoint and missing binding (T24/T03 analogue at the stub layer).**

- [ ] **Step 2: Fail**

- [ ] **Step 3: Minimal std HTTP/1.1 POST `/v1/inference.generate` with 1 MiB body cap.**

- [ ] **Step 4: PASS**

- [ ] **Step 5: Commit `feat: add instance-bound inference.generate stub`**

---

### Task 7: CLI doctor, snapshot, export, run

**Files:**
- Modify: `crates/turtle-cli/src/main.rs`
- Modify: `crates/turtle-cli/Cargo.toml` deps
- Create: `crates/turtle-cli/tests/p1_cli.rs`

**Commands:**
- `turtle doctor` prints probe JSON/text, P1 claim ceiling, exit 1 if not certified.
- `turtle snapshot import --from DIR --into DIR --select path` fail-closed without openat2.
- `turtle export --snapshot DIR --work DIR --subtree src` same.
- `turtle run --manifest FILE` compiles launch plan, probes backend, refuses to start on uncertified host with `E_UNSUPPORTED_ENFORCEMENT`. Never prints `status=enforced`.

- [ ] **Step 1: CLI tests using `CARGO_BIN_EXE_turtle`.**

- [ ] **Step 2: Fail (unknown subcommand).**

- [ ] **Step 3: Wire commands. Keep `policy check|explain|diff`.**

- [ ] **Step 4: PASS plus existing cli.rs**

- [ ] **Step 5: Commit `feat: add turtle doctor, snapshot import, export, and fail-closed run`**

---

### Task 8: Linux CI

**Files:**
- Create: `.github/workflows/ci.yml`

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: dtolnay/rust-toolchain@1.98.1
        with:
          components: rustfmt, clippy
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
```

- [ ] **Step 1: Add workflow; no test required beyond file presence.**

- [ ] **Step 2: Commit `ci: run Turtle tests on Linux`**

---

### Task 9: Documentation and evidence

**Files:**
- Modify: `README.md`, `AGENTS.md`
- Create: `docs/decisions/0006-fail-closed-uncertified-host.md`
- Create: `docs/decisions/0007-openat2-import-export.md`
- Create: `docs/evidence/p1-contained-worker.md`
- Create: `docs/p1-containment.md`

Record exact commands. State that this Windows host did not execute live gVisor tests. List T04/T05/T07/T08/T11 as Linux-gated. List T10 path classification as portable; live symlink as Linux-gated. List T24 as implemented at the stub.

- [ ] **Commit `docs: record P1 claim ceiling and uncertified-host limitation`**

---

## Out of P1 (specified, not implemented)

- Live gVisor create/inspect/start on this developer host
- MCP gateway, GitHub adapter, OAuth, vault
- SQLite daemon, approvals UI, child sandboxes
- Occupancy enforcement without cgroup attestation
- `turtle apply` writing into the owner checkout (export artifact only)
- CONNECT/`origin-egress`

## Completion gates

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. Windows: `turtle doctor` and `turtle run` exit nonzero
5. Search for `Enforced` assignments; only backend inspection may set them
6. No P2 crates

## What evidence may claim

P1 code admits a worker only when a certified Linux/gVisor/`openat2` backend is present. On this repository’s Windows development host, P1 proves fail-closed refusal, launch-plan compilation, inference-stub authorization, and portable path classification. It does not license a containment claim for that host.
