//! Turtle P1 launcher. Admission fails closed on uncertified hosts.
//!
//! Claim ceiling: local execution containment within tested backend
//! assumptions. This crate does not invent a sandbox on uncertified hosts.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod backend;
pub mod doctor;
pub mod oci;
pub mod plan;

pub use backend::{FrozenSandbox, SandboxBackend, UnsupportedBackend};
pub use doctor::{probe_host, HostProbe, P1_CLAIM_CEILING};
pub use oci::{inspect_oci, write_oci_bundle, Inspection, SandboxRequest, RUNSC_RELEASE};
pub use plan::{compile_launch_plan, EnvPlan, LaunchPlan, MountSource, MountSpec, NetworkPlan};
