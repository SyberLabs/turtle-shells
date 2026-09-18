use turtle_policy::budget::BudgetLedger;
use turtle_policy::evaluate::{evaluate, EffectRequest, Preconditions, TrustedContext};
use turtle_policy::grant::TurtleIdentity;
use turtle_policy::ids::{ActionId, OperationKey, RecipientId, ResourceId};
use turtle_policy::reason::{Decision, ReasonCode};
use turtle_policy::{compile, parse_manifest, Digest};

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

fn worker_grant() -> turtle_policy::EffectiveGrant {
    let policy = parse_manifest(WORKER).unwrap();
    compile(&policy, TurtleIdentity::root("turtle-worker-1"))
}

fn allow_ctx(grant: turtle_policy::EffectiveGrant) -> (TrustedContext, BudgetLedger) {
    let ledger = BudgetLedger::new(grant.limits.domain.clone());
    let mut ctx = TrustedContext::for_grant(grant);
    ctx.adapter_valid = true;
    (ctx, ledger)
}

fn request(action: &str, resource: &str, recipient: &str) -> EffectRequest {
    EffectRequest {
        operation_key: OperationKey::new("op1").unwrap(),
        action: ActionId::new(action).unwrap(),
        resource: ResourceId::new(resource).unwrap(),
        arguments_digest: Digest::from_bytes([0; 32]),
        recipient: RecipientId::new(recipient).unwrap(),
        preconditions: Preconditions {
            response_bytes: Some(16),
            output_tokens: Some(1),
            input_bytes: Some(16),
            ..Preconditions::default()
        },
    }
}

#[test]
fn default_deny_when_no_complete_clause_matches() {
    let grant = worker_grant();
    let (ctx, ledger) = allow_ctx(grant.clone());
    let req = request(
        "github.repository.write",
        "registry:rise-repository",
        "owner-local",
    );
    match evaluate(&grant, &req, &ctx, Some(&ledger)) {
        Decision::Deny(d) => assert_eq!(d.code, ReasonCode::EResourceOutsideGrant),
        Decision::Allow(_) => panic!("write must be denied"),
    }
}

#[test]
fn matching_read_is_allowed_when_trusted_inputs_are_set() {
    let grant = worker_grant();
    let (ctx, ledger) = allow_ctx(grant.clone());
    let req = request(
        "github.repository.read",
        "registry:rise-repository",
        "owner-local",
    );
    assert!(evaluate(&grant, &req, &ctx, Some(&ledger)).is_allow());
}

#[test]
fn explicit_deny_overrides_matching_permit() {
    let mut yaml = String::from_utf8(WORKER.to_vec()).unwrap();
    yaml = yaml.replace(
        "    - id: read-source",
        "    - id: deny-read\n      effect: deny\n      action: github.repository.read\n      resource: registry:rise-repository\n      recipients: [owner-local]\n    - id: read-source",
    );
    let policy = parse_manifest(yaml.as_bytes()).unwrap();
    let grant = compile(&policy, TurtleIdentity::root("turtle-worker-1"));
    let (ctx, ledger) = allow_ctx(grant.clone());
    let req = request(
        "github.repository.read",
        "registry:rise-repository",
        "owner-local",
    );
    match evaluate(&grant, &req, &ctx, Some(&ledger)) {
        Decision::Deny(d) => assert_eq!(d.code, ReasonCode::EPolicyDeny),
        Decision::Allow(_) => panic!("deny must win"),
    }
}

#[test]
fn unknown_action_denied() {
    let grant = worker_grant();
    let (ctx, ledger) = allow_ctx(grant.clone());
    let req = request("shell.exec", "registry:rise-repository", "owner-local");
    match evaluate(&grant, &req, &ctx, Some(&ledger)) {
        Decision::Deny(d) => assert_eq!(d.code, ReasonCode::EUnknownAction),
        Decision::Allow(_) => panic!("unknown action must deny"),
    }
}

#[test]
fn missing_adapter_validity_is_not_true() {
    let grant = worker_grant();
    let ledger = BudgetLedger::new(grant.limits.domain.clone());
    let ctx = TrustedContext::for_grant(grant.clone());
    let req = request(
        "github.repository.read",
        "registry:rise-repository",
        "owner-local",
    );
    match evaluate(&grant, &req, &ctx, Some(&ledger)) {
        Decision::Deny(d) => assert_eq!(d.code, ReasonCode::EUnsupportedEnforcement),
        Decision::Allow(_) => panic!("adapter_valid must default unsatisfied"),
    }
}

#[test]
fn inactive_turtle_is_denied() {
    let grant = worker_grant();
    let (mut ctx, ledger) = allow_ctx(grant.clone());
    ctx.turtle_active = false;
    let req = request(
        "github.repository.read",
        "registry:rise-repository",
        "owner-local",
    );
    match evaluate(&grant, &req, &ctx, Some(&ledger)) {
        Decision::Deny(d) => assert_eq!(d.code, ReasonCode::ENotActive),
        Decision::Allow(_) => panic!("inactive must deny"),
    }
}
