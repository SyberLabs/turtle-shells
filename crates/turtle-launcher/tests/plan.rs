use turtle_launcher::compile_launch_plan;
use turtle_policy::parse_manifest;

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn worker_plan_is_broker_only_and_unprivileged() {
    let policy = parse_manifest(WORKER).unwrap();
    let plan = compile_launch_plan(&policy).unwrap();
    assert!(!plan.host_network);
    assert!(!plan.privileged);
    assert!(plan.no_new_privs);
    assert!(plan.network.raw_destinations_forbidden);
    assert!(!plan.network.allow_dns);
    assert!(!plan.network.allow_udp);
    assert_eq!(plan.network.mode, "broker-only");
    assert!(!plan.env.allowlist.contains("SSH_AUTH_SOCK"));
    assert!(!plan.env.allowlist.contains("AWS_SECRET_ACCESS_KEY"));
    assert!(!plan.env.allowlist.contains("DOCKER_HOST"));
    assert!(!plan.env.allowlist.contains("GITHUB_TOKEN"));
    assert!(plan.env.inherit_none);
    let writable: Vec<_> = plan
        .mounts
        .iter()
        .filter(|m| m.writable)
        .map(|m| m.destination.as_str())
        .collect();
    assert!(writable.contains(&"/workspace/repo/src"));
    assert!(writable.contains(&"/workspace/repo/tests"));
    assert!(writable.contains(&"/tmp"));
    assert!(!writable.contains(&"/workspace/repo"));
}

#[test]
fn non_broker_network_is_rejected() {
    let yaml = String::from_utf8(WORKER.to_vec())
        .unwrap()
        .replace("mode: broker-only", "mode: origin-egress");
    let err = parse_manifest(yaml.as_bytes());
    match err {
        Err(_) => {}
        Ok(policy) => {
            assert!(compile_launch_plan(&policy).is_err());
        }
    }
}
