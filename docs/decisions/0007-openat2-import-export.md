# 0007. Snapshot import and export use openat2

## Status

Accepted for P1.

## Context

Spec §10.3 requires directory-relative operations with a trusted root handle. Canonicalizing a string and later opening it is insufficient against races. Linux `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` is the required primitive.

## Decision

Production `import_snapshot` and `export_patch` fail closed when `openat2` is unavailable. Isolated `unsafe` syscall wrappers live only in `crates/turtle-snapshot/src/linux_openat2.rs`. Import copies owner-selected regular files and directories; it rejects symlinks, devices, FIFOs, sockets, and hard links. The first worker template rejects executable export modes. `.git`, `.ssh`, `.aws`, `.gnupg`, `.docker`, and `.netrc` path segments are excluded.

## Consequences

Linux CI can exercise copy/symlink tests. Windows proves fail-closed refusal. `turtle export` does not certify that exported code is safe.
