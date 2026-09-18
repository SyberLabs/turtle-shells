//! Backend trait. Uncertified hosts cannot create a sandbox.

use turtle_policy::PolicyError;

use crate::doctor::{probe_host, HostProbe};
use crate::gvisor::GvisorBackend;
use crate::oci::SandboxRequest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenSandbox {
    pub backend_id: String,
    pub inspected: bool,
    pub instance_id: String,
    pub bundle_dir: std::path::PathBuf,
}

pub trait SandboxBackend {
    fn id(&self) -> &'static str;
    fn probe(&self) -> HostProbe;
    fn create_frozen(&self, req: &SandboxRequest<'_>) -> Result<FrozenSandbox, PolicyError>;
}

pub struct UnsupportedBackend;

impl SandboxBackend for UnsupportedBackend {
    fn id(&self) -> &'static str {
        "unsupported"
    }

    fn probe(&self) -> HostProbe {
        probe_host()
    }

    fn create_frozen(&self, _req: &SandboxRequest<'_>) -> Result<FrozenSandbox, PolicyError> {
        Err(PolicyError::unsupported(
            "no certified sandbox backend on this host",
        ))
    }
}

pub fn select_backend() -> Box<dyn SandboxBackend> {
    if probe_host().certified {
        Box::new(GvisorBackend)
    } else {
        Box::new(UnsupportedBackend)
    }
}
