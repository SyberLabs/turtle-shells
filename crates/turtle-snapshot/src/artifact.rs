#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportFile {
    pub path: String,
    pub sha256: String,
    pub mode: u32,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportArtifact {
    pub policy_digest: Option<String>,
    pub files: Vec<ExportFile>,
}
