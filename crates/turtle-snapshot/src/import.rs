use std::path::{Path, PathBuf};

use turtle_policy::path::RelPath;
use turtle_policy::PolicyError;

pub struct ImportRequest<'a> {
    pub source_root: &'a Path,
    pub selected: &'a [RelPath],
    pub dest_root: &'a Path,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub dest_root: PathBuf,
    pub files: Vec<RelPath>,
}

pub fn import_snapshot(request: &ImportRequest<'_>) -> Result<Snapshot, PolicyError> {
    if !crate::openat2_available() {
        return Err(PolicyError::unsupported("openat2 unavailable"));
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux::import_snapshot(request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        Err(PolicyError::unsupported("openat2 unavailable"))
    }
}
