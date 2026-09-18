use std::path::Path;

use turtle_policy::path::RelPath;
use turtle_policy::PolicyError;

use crate::artifact::ExportArtifact;

pub struct ExportRequest<'a> {
    pub snapshot_root: &'a Path,
    pub work_root: &'a Path,
    pub export_subtrees: &'a [RelPath],
}

pub fn export_patch(request: &ExportRequest<'_>) -> Result<ExportArtifact, PolicyError> {
    if !crate::openat2_available() {
        return Err(PolicyError::unsupported("openat2 unavailable"));
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux::export_patch(request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        Err(PolicyError::unsupported("openat2 unavailable"))
    }
}
