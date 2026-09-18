//! P1 sandbox launch plan and certified-backend probe.
//!
//! Claim ceiling: local execution containment within tested backend
//! assumptions. This crate does not invent a sandbox on uncertified hosts.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod doctor;

pub use doctor::{probe_host, HostProbe, P1_CLAIM_CEILING};
