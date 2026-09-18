use turtle_launcher::compile_launch_plan;
use turtle_launcher::oci::{inspect_oci, write_oci_bundle, SandboxRequest};
use turtle_policy::parse_manifest;

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

fn request<'a>(
    plan: &'a turtle_launcher::LaunchPlan,
    bundle: &'a std::path::Path,
    rootfs: &'a std::path::Path,
) -> SandboxRequest<'a> {
    SandboxRequest {
        plan,
        bundle_dir: bundle,
        rootfs,
    }
}

#[test]
fn oci_bundle_blocks_raw_network_and_host_sockets() {
    let policy = parse_manifest(WORKER).unwrap();
    let plan = compile_launch_plan(&policy).unwrap();
    let root = std::env::temp_dir().join(format!("turtle-oci-{}", std::process::id()));
    let bundle = root.join("bundle");
    let rootfs = root.join("rootfs");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&rootfs).unwrap();
    let config = write_oci_bundle(&request(&plan, &bundle, &rootfs)).unwrap();
    let inspection = inspect_oci(&config).unwrap();
    assert!(!inspection.host_network);
    assert!(inspection.has_network_namespace);
    assert!(inspection.network_none);
    assert!(inspection.no_new_privs);
    assert!(
        inspection.forbidden_mounts.is_empty(),
        "{:?}",
        inspection.forbidden_mounts
    );
    assert!(
        inspection.forbidden_env.is_empty(),
        "{:?}",
        inspection.forbidden_env
    );
    let spec = config.to_string();
    assert!(!spec.contains("docker.sock"));
    assert!(!spec.contains("SSH_AUTH_SOCK"));
    assert!(!spec.contains("GITHUB_TOKEN"));
    assert!(!spec.contains("/var/run/docker.sock"));
}

#[test]
fn inspect_rejects_host_network_and_docker_socket() {
    let bad = serde_json::json!({
        "process": {
            "noNewPrivileges": false,
            "env": ["SSH_AUTH_SOCK=/tmp/agent", "PATH=/bin"]
        },
        "mounts": [{
            "destination": "/var/run/docker.sock",
            "type": "bind",
            "source": "/var/run/docker.sock"
        }],
        "linux": { "namespaces": [{"type": "pid"}] }
    });
    let err = inspect_oci(&bad).unwrap_err();
    assert_eq!(
        err.reason_code(),
        turtle_policy::ReasonCode::EUnsupportedEnforcement
    );
}
