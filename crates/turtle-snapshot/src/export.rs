use std::path::Path;

use turtle_policy::path::RelPath;
use turtle_policy::PolicyError;

use crate::artifact::ExportArtifact;

pub struct ExportRequest<'a> {
    pub snapshot_root: &'a Path,
    pub work_root: &'a Path,
    pub export_subtrees: &'a [RelPath],
}

pub fn export_patch(_request: &ExportRequest<'_>) -> Result<ExportArtifact, PolicyError> {
    let _ = _request;
    Err(PolicyError::unsupported("openat2 unavailable"))
}
