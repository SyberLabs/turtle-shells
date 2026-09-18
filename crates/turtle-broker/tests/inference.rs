use serde_json::json;
use turtle_broker::{authorize_inference, mint_instance_binding};
use turtle_policy::ReasonCode;

#[test]
fn missing_or_wrong_binding_is_denied() {
    let binding = mint_instance_binding();
    let body = json!({
        "model": "registry:approved-model",
        "messages": [{"role": "user", "content": "hi"}],
        "maxOutputTokens": 16
    });
    let err = authorize_inference(&binding, None, &body).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::EIdentity);
    let err = authorize_inference(&binding, Some(b"deadbeef"), &body).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::EIdentity);
}

#[test]
fn caller_selected_endpoint_and_tools_are_rejected() {
    let binding = mint_instance_binding();
    for key in [
        "baseUrl",
        "base_url",
        "tools",
        "file_ids",
        "uploads",
        "background",
    ] {
        let mut body = json!({
            "model": "registry:approved-model",
            "messages": [{"role": "user", "content": "hi"}],
            "maxOutputTokens": 16
        });
        body[key] = json!("attacker");
        let err = authorize_inference(&binding, Some(&binding.secret), &body).unwrap_err();
        assert_eq!(
            err.reason_code(),
            ReasonCode::EUnsupportedEnforcement,
            "{key}"
        );
    }
}

#[test]
fn typed_generate_is_accepted() {
    let binding = mint_instance_binding();
    let body = json!({
        "model": "registry:approved-model",
        "messages": [{"role": "user", "content": "hi"}],
        "maxOutputTokens": 16
    });
    let req = authorize_inference(&binding, Some(&binding.secret), &body).unwrap();
    assert_eq!(req.model, "registry:approved-model");
    assert_eq!(req.max_output_tokens, 16);
}
