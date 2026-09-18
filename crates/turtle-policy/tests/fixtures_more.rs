use turtle_policy::{parse_manifest, ReasonCode};

fn parse_named(name: &str, bytes: &[u8]) {
    let err = parse_manifest(bytes).expect_err(name);
    assert_eq!(err.reason_code(), ReasonCode::ESchema, "{name}: {err}");
}

#[test]
fn malformed_fixtures_are_e_schema_without_panic() {
    parse_named(
        "duplicate-keys",
        include_bytes!("../../../tests/fixtures/malformed/duplicate-keys.yaml"),
    );
    parse_named(
        "alias",
        include_bytes!("../../../tests/fixtures/malformed/alias.yaml"),
    );
    parse_named(
        "merge-key",
        include_bytes!("../../../tests/fixtures/malformed/merge-key.yaml"),
    );
    parse_named(
        "custom-tag",
        include_bytes!("../../../tests/fixtures/malformed/custom-tag.yaml"),
    );
    parse_named(
        "nonfinite",
        include_bytes!("../../../tests/fixtures/malformed/nonfinite.yaml"),
    );
    parse_named(
        "unknown-field",
        include_bytes!("../../../tests/fixtures/malformed/unknown-field.yaml"),
    );
}

#[test]
fn unsupported_constraint_fails_closed() {
    let err = parse_manifest(include_bytes!(
        "../../../tests/fixtures/malformed/unsupported-constraint.yaml"
    ))
    .unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::EUnsupportedEnforcement);
}

#[test]
fn additional_valid_fixtures_parse() {
    parse_manifest(include_bytes!(
        "../../../tests/fixtures/valid/attenuated-child.yaml"
    ))
    .unwrap();
    parse_manifest(include_bytes!(
        "../../../tests/fixtures/valid/all-supported-constraints.yaml"
    ))
    .unwrap();
}
