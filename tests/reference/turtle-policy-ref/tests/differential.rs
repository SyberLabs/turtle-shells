use turtle_policy::budget::BudgetLedger;
use turtle_policy::evaluate::{evaluate, EffectRequest, Preconditions, TrustedContext};
use turtle_policy::grant::TurtleIdentity;
use turtle_policy::ids::{ActionId, OperationKey, RecipientId, ResourceId};
use turtle_policy::reason::Decision;
use turtle_policy::{compile, parse_manifest, Digest};
use turtle_policy_ref::decide;

const WORKER: &[u8] = include_bytes!("../../../../tests/fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn production_and_reference_agree_on_worker_fixture() {
    let policy = parse_manifest(WORKER).unwrap();
    let grant = compile(&policy, TurtleIdentity::root("t1"));
    let ledger = BudgetLedger::new(grant.limits.domain.clone());
    let mut ctx = TrustedContext::for_grant(grant.clone());
    ctx.adapter_valid = true;
    let requests = [
        (
            "github.repository.read",
            "registry:rise-repository",
            "owner-local",
        ),
        (
            "github.repository.write",
            "registry:rise-repository",
            "owner-local",
        ),
        ("github.repository.read", "registry:other", "owner-local"),
        (
            "inference.generate",
            "registry:approved-model",
            "approved-inference-provider",
        ),
    ];
    for (i, (action, resource, recipient)) in requests.iter().enumerate() {
        let req = EffectRequest {
            operation_key: OperationKey::new(format!("op{i}")).unwrap(),
            action: ActionId::new(*action).unwrap(),
            resource: ResourceId::new(*resource).unwrap(),
            arguments_digest: Digest::from_bytes([0; 32]),
            recipient: RecipientId::new(*recipient).unwrap(),
            preconditions: Preconditions {
                input_bytes: Some(8),
                output_tokens: Some(1),
                response_bytes: Some(8),
                ..Preconditions::default()
            },
        };
        let production = evaluate(&grant, &req, &ctx, Some(&ledger));
        let reference = decide(&grant, &req, &ctx);
        assert_eq!(
            production.is_allow(),
            reference.is_allow(),
            "{action} {resource} {recipient} prod={production:?} ref={reference:?}"
        );
        if let (Decision::Deny(a), Decision::Deny(b)) = (&production, &reference) {
            assert_eq!(a.code, b.code, "{action} {resource}");
        }
    }
}
