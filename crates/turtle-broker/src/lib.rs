//! P1 inference stub. Not a provider credential broker.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod identity;
pub mod inference;
pub mod server;

pub use identity::{mint_instance_binding, InstanceBinding};
pub use inference::{authorize_inference, InferenceGenerateRequest, InferenceMessage};
pub use server::serve;
