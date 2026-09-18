//! Host-side snapshot import and export.
//!
//! Production copy uses Linux `openat2`. Other hosts fail closed.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod artifact;
pub mod classify;
pub mod export;
pub mod import;

pub use artifact::{ExportArtifact, ExportFile};
pub use classify::{classify_relative_path, is_excluded_name};
pub use export::{export_patch, ExportRequest};
pub use import::{import_snapshot, ImportRequest, Snapshot};
