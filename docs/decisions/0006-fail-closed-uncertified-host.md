# 0006. Fail closed on an uncertified host

## Status

Accepted for P1.

## Context

P1’s claim ceiling is local execution containment within tested backend assumptions. The certified backend is Linux OCI through gVisor `runsc`, with `openat2` for import/export. The first development host was Windows without WSL, Docker, or gVisor.

## Decision

`turtle doctor` and `turtle run` return `E_UNSUPPORTED_ENFORCEMENT` unless the host probe is certified. There is no userspace or Windows sandbox backend. A missing primitive is an admission failure, not a weaker successful launch.

## Consequences

Windows and other uncertified hosts can compile launch plans, classify snapshot paths, and exercise the inference stub. They cannot claim containment. Live T04/T05/T07 tests remain Linux-gated.
