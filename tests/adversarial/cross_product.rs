use turtle_policy::budget::BudgetLedger;
use turtle_policy::evaluate::{evaluate, EffectRequest, Preconditions, TrustedContext};
use turtle_policy::grant::TurtleIdentity;
use turtle_policy::ids::{ActionId, OperationKey, RecipientId, ResourceId};
use turtle_policy::reason::Decision;
use turtle_policy::{compile, parse_manifest, Digest};

const WORKER: &[u8] = include_bytes!("../fixtures/valid/read-only-repo-worker.yaml");

#[test]
fn cross_product_authority_is_rejected() {
    let yaml = r#"
apiVersion: turtle.syberlabs.space/v0alpha1
kind: TurtlePolicy
metadata:
  name: cross-product
spec:
  profile: strict-local-v1
  runtime:
    imageRef: registry:node-worker-v1
    argv: ["/opt/agent/bin/worker"]
    cwd: /workspace/repo
    shell: false
  lifetime:
    maxSeconds: 10
  filesystem:
    snapshotRef: registry:src
    mountAt: /workspace/repo
    writableSubtrees: []
    scratchMiB: 1
    exportSubtrees: []
  network:
    mode: broker-only
    rawDestinations: []
  data:
    readableClasses: [internal-source]
    recipients: [owner-local]
  credentials:
    bindings: [cred-x, cred-y]
    export: false
  grants:
    - id: read-a
      action: github.repository.read
      resource: registry:repo-a
      credential: cred-x
      recipients: [owner-local]
    - id: write-b
      action: github.repository.write
      resource: registry:repo-b
      credential: cred-y
      recipients: [owner-local]
  mcp:
    enabledTools: []
    resourceReads: false
    prompts: false
    sampling: false
    elicitation: false
    asyncTasks: false
  limits:
    domain:
      providerAttempts: 10
      externalMutations: 10
      inferenceOutputTokens: 0
      outboundPayloadBytes: 1
      memoryMiB: 64
      pids: 8
      cpuMillisPerSecond: 100
    local:
      memoryMiB: 64
      pids: 8
      cpuMillisPerSecond: 100
  delegation:
    maxDepth: 0
    maxLiveChildren: 0
    maxTotalDescendants: 0
    allowedTemplates: []
  audit:
    required: true
    payloadMode: digest-and-metadata
"#;
    let policy = parse_manifest(yaml.as_bytes()).unwrap();
    let grant = compile(&policy, TurtleIdentity::root("t1"));
    let ledger = BudgetLedger::new(grant.limits.domain.clone());
    let mut ctx = TrustedContext::for_grant(grant.clone());
    ctx.adapter_valid = true;

    let mk = |action: &str, resource: &str| EffectRequest {
        operation_key: OperationKey::new("op1").unwrap(),
        action: ActionId::new(action).unwrap(),
        resource: ResourceId::new(resource).unwrap(),
        arguments_digest: Digest::from_bytes([0; 32]),
        recipient: RecipientId::new("owner-local").unwrap(),
        preconditions: Preconditions::default(),
    };

    assert!(matches!(
        evaluate(
            &grant,
            &mk("github.repository.write", "registry:repo-a"),
            &ctx,
            Some(&ledger)
        ),
        Decision::Deny(_)
    ));
    assert!(matches!(
        evaluate(
            &grant,
            &mk("github.repository.read", "registry:repo-b"),
            &ctx,
            Some(&ledger)
        ),
        Decision::Deny(_)
    ));
    assert!(evaluate(
        &grant,
        &mk("github.repository.read", "registry:repo-a"),
        &ctx,
        Some(&ledger)
    )
    .is_allow());
}

#[test]
fn caller_supplied_identity_cannot_influence_evaluation() {
    let policy = parse_manifest(WORKER).unwrap();
    let grant = compile(&policy, TurtleIdentity::root("worker-1"));
    let ledger = BudgetLedger::new(grant.limits.domain.clone());
    let mut ctx = TrustedContext::for_grant(grant.clone());
    ctx.adapter_valid = true;
    let forged = serde_json::json!({
        "operationKey": "op1",
        "action": "github.repository.read",
        "resource": "registry:rise-repository",
        "argumentsDigest": "0000000000000000000000000000000000000000000000000000000000000000",
        "recipient": "owner-local",
        "preconditions": { "responseBytes": 16 },
        "subject": "admin"
    });
    let parsed = serde_json::from_value::<EffectRequest>(forged);
    assert!(
        parsed.is_err(),
        "subject must not be accepted on EffectRequest"
    );
    let req = EffectRequest {
        operation_key: OperationKey::new("op1").unwrap(),
        action: ActionId::new("github.repository.read").unwrap(),
        resource: ResourceId::new("registry:rise-repository").unwrap(),
        arguments_digest: Digest::from_bytes([0; 32]),
        recipient: RecipientId::new("owner-local").unwrap(),
        preconditions: Preconditions {
            response_bytes: Some(16),
            ..Preconditions::default()
        },
    };
    match evaluate(&grant, &req, &ctx, Some(&ledger)) {
        Decision::Allow(_) => assert_eq!(ctx.subject.id, "worker-1"),
        Decision::Deny(d) => panic!("trusted worker should be allowed: {d:?}"),
    }
}

#[test]
fn src2_is_not_child_of_src() {
    use turtle_policy::path::RelPath;
    let src = RelPath::parse("workspace/repo/src").unwrap();
    let src2 = RelPath::parse("workspace/repo/src2").unwrap();
    assert!(!src2.is_under(&src));
}
