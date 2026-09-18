use turtle_policy::{enforcement_plan, parse_manifest, EnforcementStatus};

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn p0_plan_never_claims_enforced() {
    let policy = parse_manifest(WORKER).unwrap();
    let plan = enforcement_plan(&policy);
    assert_eq!(plan.claim_ceiling, turtle_policy::CLAIM_CEILING);
    assert!(plan
        .requirements
        .iter()
        .all(|r| r.status != EnforcementStatus::Enforced));
    assert!(plan
        .requirements
        .iter()
        .all(|r| r.limitation.contains("not deployed in P0")));
}
