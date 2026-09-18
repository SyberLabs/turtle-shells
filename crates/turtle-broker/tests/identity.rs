use turtle_broker::mint_instance_binding;

#[test]
fn sibling_binding_does_not_authenticate() {
    let a = mint_instance_binding();
    let b = mint_instance_binding();
    assert_ne!(a.secret, b.secret);
    assert_ne!(a.instance_id, b.instance_id);
    assert!(!turtle_broker::identity::presented_secret_matches(
        &a, &b.secret
    ));
}
