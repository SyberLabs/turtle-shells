use turtle_policy::parse_manifest;
use turtle_policy::ReasonCode;

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");
const UNKNOWN_FIELD: &[u8] = include_bytes!("../../../tests/fixtures/malformed/unknown-field.yaml");
const UNKNOWN_ACTION: &[u8] =
    include_bytes!("../../../tests/fixtures/malformed/unknown-action.yaml");
const TRAVERSAL: &[u8] = include_bytes!("../../../tests/fixtures/malformed/path-traversal.yaml");
const ABSOLUTE: &[u8] = include_bytes!("../../../tests/fixtures/malformed/absolute-path.yaml");

#[test]
fn minimal_worker_parses() {
    let policy = parse_manifest(WORKER).unwrap();
    assert_eq!(policy.name(), "rise-worker");
    assert_eq!(policy.clauses().len(), 2);
}

#[test]
fn unknown_field_is_e_schema() {
    let err = parse_manifest(UNKNOWN_FIELD).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn unknown_action_is_e_unknown_action() {
    let err = parse_manifest(UNKNOWN_ACTION).unwrap_err();
    assert_eq!(
        err.reason_code(),
        ReasonCode::EUnknownAction,
        "error was {err}"
    );
}

#[test]
fn path_traversal_rejected() {
    let err = parse_manifest(TRAVERSAL).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn absolute_path_rejected() {
    let err = parse_manifest(ABSOLUTE).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn excessive_clauses_rejected() {
    let mut grants = String::new();
    for i in 0..129 {
        grants.push_str(&format!(
            "    - id: c{i}\n      action: github.repository.read\n      resource: registry:src\n      recipients: [owner-local]\n"
        ));
    }
    let yaml = format!(
        "apiVersion: turtle.syberlabs.space/v0alpha1\nkind: TurtlePolicy\nmetadata:\n  name: too-many\nspec:\n  profile: strict-local-v1\n  runtime:\n    imageRef: registry:node-worker-v1\n    argv: [\"/opt/agent/bin/worker\"]\n    cwd: /workspace/repo\n    shell: false\n  lifetime:\n    maxSeconds: 10\n  filesystem:\n    snapshotRef: registry:src\n    mountAt: /workspace/repo\n    writableSubtrees: []\n    scratchMiB: 1\n    exportSubtrees: []\n  network:\n    mode: broker-only\n    rawDestinations: []\n  data:\n    readableClasses: [internal-source]\n    recipients: [owner-local]\n  credentials:\n    bindings: []\n    export: false\n  grants:\n{grants}  mcp:\n    enabledTools: []\n    resourceReads: false\n    prompts: false\n    sampling: false\n    elicitation: false\n    asyncTasks: false\n  limits:\n    domain:\n      providerAttempts: 1\n      externalMutations: 0\n      inferenceOutputTokens: 0\n      outboundPayloadBytes: 1\n      memoryMiB: 64\n      pids: 8\n      cpuMillisPerSecond: 100\n    local:\n      memoryMiB: 64\n      pids: 8\n      cpuMillisPerSecond: 100\n  delegation:\n    maxDepth: 0\n    maxLiveChildren: 0\n    maxTotalDescendants: 0\n    allowedTemplates: []\n  audit:\n    required: true\n    payloadMode: digest-and-metadata\n"
    );
    let err = parse_manifest(yaml.as_bytes()).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}
