//! Closed v0 action registry. Unknown actions fail closed.

use crate::ids::ActionId;

pub const REGISTERED_ACTIONS: &[&str] = &[
    "inference.generate",
    "github.repository.read",
    "github.repository.write",
    "turtle.delegate",
    "artifact.export",
];

pub fn is_registered_action(action: &ActionId) -> bool {
    REGISTERED_ACTIONS.contains(&action.as_str())
}

pub fn is_registered_action_str(action: &str) -> bool {
    REGISTERED_ACTIONS.contains(&action)
}
