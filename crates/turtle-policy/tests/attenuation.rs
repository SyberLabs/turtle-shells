use turtle_policy::check_attenuation;
use turtle_policy::grant::TurtleIdentity;
use turtle_policy::ids::{ActionId, RecipientId};
use turtle_policy::reason::ReasonCode;
use turtle_policy::{compile, parse_manifest};

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

fn parent() -> turtle_policy::EffectiveGrant {
    let policy = parse_manifest(WORKER).unwrap();
    compile(&policy, TurtleIdentity::root("turtle-worker-1"))
}

fn child_from(parent: &turtle_policy::EffectiveGrant) -> turtle_policy::EffectiveGrant {
    let mut child = parent.clone();
    child.identity = TurtleIdentity {
        id: "child-1".to_string(),
        root_id: parent.identity.root_id.clone(),
        parent_id: Some(parent.identity.id.clone()),
        subject_binding: "child-1".to_string(),
    };
    child.delegation.max_depth = 0;
    child.lifetime.max_seconds = parent.lifetime.max_seconds.saturating_sub(1);
    child
}

#[test]
fn earlier_child_expiry_accepted() {
    let parent = parent();
    let child = child_from(&parent);
    check_attenuation(&parent, &child).unwrap();
}

#[test]
fn later_child_expiry_rejected() {
    let parent = parent();
    let mut child = child_from(&parent);
    child.lifetime.max_seconds = parent.lifetime.max_seconds + 1;
    let err = check_attenuation(&parent, &child).unwrap_err();
    assert_eq!(err.code, ReasonCode::EDelegationWidens);
}

#[test]
fn child_action_widening_rejected() {
    let parent = parent();
    let mut child = child_from(&parent);
    child.clauses[1]
        .actions
        .insert(ActionId::new("github.repository.write").unwrap());
    let err = check_attenuation(&parent, &child).unwrap_err();
    assert_eq!(err.code, ReasonCode::EDelegationWidens);
}

#[test]
fn child_recipient_widening_rejected() {
    let parent = parent();
    let mut child = child_from(&parent);
    child.clauses[1]
        .recipients
        .insert(RecipientId::new("public-issue-tracker").unwrap());
    let err = check_attenuation(&parent, &child).unwrap_err();
    assert_eq!(err.code, ReasonCode::EDelegationWidens);
}

#[test]
fn credential_substitution_rejected() {
    let parent = parent();
    let mut child = child_from(&parent);
    child.clauses[1].credential =
        Some(turtle_policy::ids::CredentialBindingId::new("other-cred").unwrap());
    let err = check_attenuation(&parent, &child).unwrap_err();
    assert_eq!(err.code, ReasonCode::EDelegationWidens);
}

#[test]
fn child_depth_beyond_remaining_rejected() {
    let parent = parent();
    let mut child = child_from(&parent);
    child.delegation.max_depth = 1;
    let err = check_attenuation(&parent, &child).unwrap_err();
    assert_eq!(err.code, ReasonCode::EDepth);
}

#[test]
fn union_of_two_parent_clauses_rejected() {
    let parent = parent();
    let mut child = child_from(&parent);
    let write = ActionId::new("github.repository.write").unwrap();
    child.clauses[0].actions.insert(write);
    child.clauses[0].resources = parent.clauses[1].resources.clone();
    let err = check_attenuation(&parent, &child).unwrap_err();
    assert_eq!(err.code, ReasonCode::EDelegationWidens);
}
