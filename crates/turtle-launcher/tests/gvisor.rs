use turtle_launcher::backend::{select_backend, SandboxBackend};
use turtle_launcher::compile_launch_plan;
use turtle_launcher::gvisor::GvisorBackend;
use turtle_launcher::oci::SandboxRequest;
use turtle_launcher::probe_host;
use turtle_policy::parse_manifest;
use turtle_policy::ReasonCode;

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn gvisor_backend_fails_closed_when_host_is_uncertified() {
    if probe_host().certified {
        return;
    }
    let policy = parse_manifest(WORKER).unwrap();
    let plan = compile_launch_plan(&policy).unwrap();
    let root = std::env::temp_dir().join(format!("turtle-gvisor-{}", std::process::id()));
    let bundle = root.join("bundle");
    let rootfs = root.join("rootfs");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&rootfs).unwrap();
    let err = GvisorBackend
        .create_frozen(&SandboxRequest {
            plan: &plan,
            bundle_dir: &bundle,
            rootfs: &rootfs,
        })
        .unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::EUnsupportedEnforcement);
    assert_eq!(select_backend().id(), "unsupported");
}

#[test]
fn select_backend_is_gvisor_only_when_certified() {
    let backend = select_backend();
    if probe_host().certified {
        assert_eq!(backend.id(), "gvisor-runsc");
    } else {
        assert_eq!(backend.id(), "unsupported");
    }
}
