# P1 evidence report

**Date:** 18 September 2026  
**Host:** Windows 10, rustc 1.98.1 (`x86_64-pc-windows-gnu`). No WSL, Docker, or gVisor `runsc`.  
**P1 claim ceiling:** Local execution containment within tested backend assumptions.

This report records commands actually run. It does not license a containment claim for this Windows host.

## Commands and results

### Format and lint

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

`fmt_exit=0`. `clippy_exit=0`.

### Tests

```
cargo test --workspace
```

`test_exit=0`. **68 passed, 0 failed** on this host. Linux-only `openat2` copy/symlink tests compiled as empty (`linux_import.rs` ran 0 tests). `cargo check -p turtle-snapshot --target x86_64-unknown-linux-gnu` succeeded earlier in the same branch.

### Doctor and run (this host)

```
cargo run -p turtle-cli -- doctor
```

Exit 1:

```
claim_ceiling: Local execution containment within tested backend assumptions.
os=windows
openat2=false
runsc=none
certified=false
failure=host is windows, not Linux
failure=openat2 unavailable
failure=gVisor runsc not found on PATH
```

```
cargo run -p turtle-cli -- run --manifest tests/fixtures/valid/read-only-repo-worker.yaml
```

Exit 1. Compiled `host_network=false`, then:

```
{"code":"E_UNSUPPORTED_ENFORCEMENT","explanation":"no certified sandbox backend on this host","retryable":false}
```

No `status=enforced` output.

## Attack matrix coverage on this host

| ID | Result here |
|---|---|
| T10 path classification / excluded dirs | Portable tests passed |
| T10 live symlink import | Linux-gated; not executed on Windows |
| T12 executable export mode | Linux-gated |
| T24 caller-selected inference URL/tools | Stub tests passed |
| T03 sibling binding replay (stub) | Passed |
| T04/T05/T07/T08/T11 live sandbox | Not executed; host uncertified |

## What this evidence licenses

P1 may be described as fail-closed admission, launch-plan compilation, Linux `openat2` import/export (compiled; live copy tests pending Linux CI), and an instance-bound inference stub. It may not be described as a sandbox on this Windows host, a credential broker, or a production-ready authorization system.

## Next smallest milestone

Certified Linux host with `runsc`: implement `GvisorBackend::create_frozen` inspect-before-start, then live T04/T05/T07. P2 remains MCP/provider adapters.
