use turtle_policy::reason::ReasonCode;
use turtle_policy::yaml::yaml_to_json;

#[test]
fn duplicate_keys_are_rejected() {
    let err = yaml_to_json(b"a: 1\na: 2\n").unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn aliases_are_rejected() {
    let err = yaml_to_json(b"x: &a 1\ny: *a\n").unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn merge_keys_are_rejected() {
    let err = yaml_to_json(b"a: &id\n  x: 1\nb:\n  <<: *id\n").unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn custom_tags_are_rejected() {
    let err = yaml_to_json(b"x: !foo 1\n").unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn yes_is_not_coerced_to_bool() {
    let err = yaml_to_json(b"x: yes\n").unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn nonfinite_numbers_are_rejected() {
    assert_eq!(
        yaml_to_json(b"x: .inf\n").unwrap_err().reason_code(),
        ReasonCode::ESchema
    );
    assert_eq!(
        yaml_to_json(b"x: .nan\n").unwrap_err().reason_code(),
        ReasonCode::ESchema
    );
}

#[test]
fn nesting_beyond_16_is_rejected() {
    let mut s = String::new();
    for _ in 0..17 {
        s.push_str("{a: ");
    }
    s.push('1');
    for _ in 0..17 {
        s.push('}');
    }
    let err = yaml_to_json(s.as_bytes()).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn oversized_manifest_is_rejected() {
    let too_big = vec![b'x'; 262_145];
    let err = yaml_to_json(&too_big).unwrap_err();
    assert_eq!(err.reason_code(), ReasonCode::ESchema);
}

#[test]
fn quoted_strings_and_bools_parse() {
    let value = yaml_to_json(b"a: \"yes\"\nb: true\nc: 0\nd: 12\n").unwrap();
    assert_eq!(value["a"], "yes");
    assert_eq!(value["b"], true);
    assert_eq!(value["c"], 0);
    assert_eq!(value["d"], 12);
}
