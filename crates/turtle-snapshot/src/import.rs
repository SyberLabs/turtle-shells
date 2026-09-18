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

pub fn import_snapshot(_request: &ImportRequest<'_>) -> Result<Snapshot, PolicyError> {
    let _ = _request;
    Err(PolicyError::unsupported("openat2 unavailable"))
}
