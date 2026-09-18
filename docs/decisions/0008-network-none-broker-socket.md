# 0008. P1 network-none plus unix broker socket

## Status

Accepted for the gVisor run slice.

## Context

Spec §11.1 asks for one isolated virtual network attachment that admits only the broker. A general IP stack plus allowlists is easy to get wrong (DNS, IPv6, metadata, rebinding). T04/T05 require host-side proof that packets do not reach forbidden destinations.

## Decision

P1 gVisor sandboxes are created with `--network=none` and an OCI annotation `org.syberlabs.turtle.network=none`. The inference stub is reached over a unix socket at `/run/turtle/broker.sock` when mounted, not over a guest IP route. This is stricter than a broker-only veth: there is no path to `1.1.1.1`, `169.254.169.254`, host loopback, or sibling nets.

Live tests start a host TCP canary and fail if it accepts a connection from the guest.

## Consequences

P1 cannot use IP-based MCP or HTTP-from-guest except through a later explicit dataplane. That dataplane is P2. `inspect_oci` rejects host network, docker/SSH/browser sockets, and inherited secret environment variables before `runsc create`.
