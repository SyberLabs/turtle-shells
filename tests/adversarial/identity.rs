//! Caller-supplied identity must not become authority.

use turtle_policy::evaluate::EffectRequest;

#[test]
fn effect_request_rejects_subject_field() {
    let forged = serde_json::json!({
        "operationKey": "op1",
        "action": "github.repository.read",
        "resource": "registry:src",
        "argumentsDigest": "0000000000000000000000000000000000000000000000000000000000000000",
        "recipient": "owner-local",
        "preconditions": {},
        "subject": "admin"
    });
    assert!(serde_json::from_value::<EffectRequest>(forged).is_err());
}
