//! Backend trait. Uncertified hosts cannot create a sandbox.

use turtle_policy::PolicyError;

use crate::doctor::{probe_host, HostProbe};
use crate::plan::LaunchPlan;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenSandbox {
    pub backend_id: String,
    pub inspected: bool,
}

pub trait SandboxBackend {
    fn id(&self) -> &'static str;
    fn probe(&self) -> HostProbe;
    fn create_frozen(&self, plan: &LaunchPlan) -> Result<FrozenSandbox, PolicyError>;
}

pub struct UnsupportedBackend;

impl SandboxBackend for UnsupportedBackend {
    fn id(&self) -> &'static str {
        "unsupported"
    }

    fn probe(&self) -> HostProbe {
        probe_host()
    }

    fn create_frozen(&self, _plan: &LaunchPlan) -> Result<FrozenSandbox, PolicyError> {
        Err(PolicyError::unsupported(
            "no certified sandbox backend on this host",
        ))
    }
}
