//! Turtle P0 semantic kernel.
//!
//! Claim ceiling: pure policy evaluator, delegation checker, and simulated
//! budgets. No containment claim.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod actions;
pub mod constraints;
pub mod digest;
pub mod error;
pub mod grant;
pub mod ids;
pub mod jcs;
pub mod limits;
pub mod manifest;
pub mod path;
pub mod reason;
pub mod schema;
pub mod yaml;

pub use digest::{policy_digest, Digest};
pub use error::PolicyError;
pub use grant::{EffectiveGrant, GrantClause, TurtleIdentity, TurtlePolicy};
pub use manifest::parse_manifest;
pub use reason::{Decision, DecisionEvidence, Denial, ReasonCode};

pub const API_VERSION: &str = "turtle.syberlabs.space/v0alpha1";
pub const CLAIM_CEILING: &str =
    "Pure policy evaluator, delegation checker, and simulated budgets. No containment claim.";

pub fn compile(policy: &TurtlePolicy, identity: TurtleIdentity) -> EffectiveGrant {
    policy.compile(identity)
}
