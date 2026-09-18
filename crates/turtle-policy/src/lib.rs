//! Turtle P0 semantic kernel.
//!
//! Claim ceiling: pure policy evaluator, delegation checker, and simulated
//! budgets. No containment claim.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod error;
pub mod reason;

pub use error::PolicyError;
pub use reason::{Decision, DecisionEvidence, Denial, ReasonCode};

pub const API_VERSION: &str = "turtle.syberlabs.space/v0alpha1";
pub const CLAIM_CEILING: &str =
    "Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.";
