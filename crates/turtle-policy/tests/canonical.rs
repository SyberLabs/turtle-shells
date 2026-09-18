use turtle_policy::{parse_manifest, policy_digest};

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn equivalent_parse_is_stable() {
    let a = parse_manifest(WORKER).unwrap();
    let b = parse_manifest(WORKER).unwrap();
    assert_eq!(policy_digest(&a).unwrap(), policy_digest(&b).unwrap());
}

#[test]
fn different_constraints_change_digest() {
    let a = parse_manifest(WORKER).unwrap();
    let mut yaml = String::from_utf8(WORKER.to_vec()).unwrap();
    yaml = yaml.replace("maxResponseBytes: 1048576", "maxResponseBytes: 1048575");
    let b = parse_manifest(yaml.as_bytes()).unwrap();
    assert_ne!(policy_digest(&a).unwrap().hex(), policy_digest(&b).unwrap().hex());
}
