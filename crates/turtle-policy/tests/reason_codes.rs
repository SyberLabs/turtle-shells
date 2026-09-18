use turtle_policy::reason::ReasonCode;

const REQUIRED: &[&str] = &[
    "E_SCHEMA",
    "E_UNKNOWN_ACTION",
    "E_IDENTITY",
    "E_NOT_ACTIVE",
    "E_ANCESTOR_REVOKED",
    "E_EXPIRED",
    "E_POLICY_DENY",
    "E_RESOURCE_OUTSIDE_GRANT",
    "E_DISCLOSURE",
    "E_APPROVAL_REQUIRED",
    "E_APPROVAL_STALE",
    "E_BUDGET",
    "E_DELEGATION_WIDENS",
    "E_DEPTH",
    "E_UNSUPPORTED_ENFORCEMENT",
    "E_DRIVER_DRIFT",
    "E_PRECONDITION",
    "E_OPERATION_CONFLICT",
    "E_OUTCOME_UNKNOWN",
    "E_AUDIT_UNAVAILABLE",
];

#[test]
fn every_stable_reason_code_round_trips() {
    for code in REQUIRED {
        let parsed: ReasonCode = code.parse().expect(code);
        assert_eq!(parsed.to_string(), *code);
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, format!("\"{code}\""));
        let back: ReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, parsed);
    }
}

#[test]
fn unknown_reason_code_is_rejected() {
    assert!("E_MADE_UP".parse::<ReasonCode>().is_err());
}
