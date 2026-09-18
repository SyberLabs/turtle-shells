#[test]
fn reference_crate_does_not_import_production_decide() {
    let src = include_str!("../src/lib.rs");
    assert!(!src.contains("turtle_policy::evaluate::evaluate"));
    assert!(!src.contains("evaluate_layers("));
    assert!(!src.contains("use turtle_policy::evaluate"));
}
