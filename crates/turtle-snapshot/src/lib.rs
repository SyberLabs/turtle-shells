//! Host-side snapshot import and export.
//!
//! Production copy uses Linux `openat2`. Other hosts fail closed.

#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![cfg_attr(target_os = "linux", deny(unsafe_code))]
#![deny(clippy::all)]

pub mod artifact;
pub mod classify;
pub mod export;
pub mod import;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_openat2;

pub use artifact::{ExportArtifact, ExportFile};
pub use classify::{classify_relative_path, is_excluded_name};
pub use export::{export_patch, ExportRequest};
pub use import::{import_snapshot, ImportRequest, Snapshot};

pub fn openat2_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::openat2_available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
