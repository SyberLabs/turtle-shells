//! Host-side snapshot import and export.
//!
//! Production copy uses Linux `openat2`. Other hosts fail closed.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod classify;

pub use classify::{classify_relative_path, is_excluded_name};
