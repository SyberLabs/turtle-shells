use turtle_policy::budget::BudgetLedger;
use turtle_policy::check_attenuation;
use turtle_policy::evaluate::{evaluate, EffectRequest, Preconditions, TrustedContext};
use turtle_policy::grant::TurtleIdentity;
use turtle_policy::ids::{ActionId, OperationKey, RecipientId, ResourceId};
use turtle_policy::{compile, parse_manifest, Digest};

const WORKER: &[u8] = include_bytes!("../../../../tests/fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn attenuated_child_cannot_allow_parent_denied_request() {
    let parent_policy = parse_manifest(WORKER).unwrap();
    let parent = compile(&parent_policy, TurtleIdentity::root("turtle-worker-1"));
    let child_policy = parse_manifest(include_bytes!(
        "../../../../tests/fixtures/valid/attenuated-child.yaml"
    ))
    .unwrap();
    let mut child = compile(
        &child_policy,
        TurtleIdentity {
            id: "child-1".into(),
            root_id: "turtle-worker-1".into(),
            parent_id: Some("turtle-worker-1".into()),
            subject_binding: "child-1".into(),
        },
    );
    child.delegation.max_depth = 0;
    check_attenuation(&parent, &child).expect("valid child must attenuate");

    let ledger = BudgetLedger::new(parent.limits.domain.clone());
    let mut ctx = TrustedContext::for_grant(parent.clone());
    ctx.adapter_valid = true;
    let denied_by_parent = EffectRequest {
        operation_key: OperationKey::new("op-write").unwrap(),
        action: ActionId::new("github.repository.write").unwrap(),
        resource: ResourceId::new("registry:rise-repository").unwrap(),
        arguments_digest: Digest::from_bytes([0; 32]),
        recipient: RecipientId::new("owner-local").unwrap(),
        preconditions: Preconditions::default(),
    };
    assert!(!evaluate(&parent, &denied_by_parent, &ctx, Some(&ledger)).is_allow());
    let mut child_ctx = TrustedContext::for_grant(child.clone());
    child_ctx.adapter_valid = true;
    let child_ledger = BudgetLedger::new(child.limits.domain.clone());
    assert!(!evaluate(&child, &denied_by_parent, &child_ctx, Some(&child_ledger)).is_allow());
}

#[test]
fn widening_recipient_child_is_rejected() {
    let parent_policy = parse_manifest(WORKER).unwrap();
    let parent = compile(&parent_policy, TurtleIdentity::root("turtle-worker-1"));
    let child_policy = parse_manifest(include_bytes!(
        "../../../../tests/fixtures/invalid/child-widens-recipients.yaml"
    ))
    .unwrap();
    let child = compile(
        &child_policy,
        TurtleIdentity {
            id: "child-1".into(),
            root_id: "turtle-worker-1".into(),
            parent_id: Some("turtle-worker-1".into()),
            subject_binding: "child-1".into(),
        },
    );
    assert!(check_attenuation(&parent, &child).is_err());
}
