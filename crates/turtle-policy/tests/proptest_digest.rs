use proptest::prelude::*;
use turtle_policy::{parse_manifest, policy_digest};

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]
    #[test]
    fn distinct_response_limits_change_digest(limit in 1u32..1_000_000u32) {
        let a = parse_manifest(WORKER).unwrap();
        let yaml = String::from_utf8(WORKER.to_vec()).unwrap().replace(
            "maxResponseBytes: 1048576",
            &format!("maxResponseBytes: {limit}"),
        );
        let b = parse_manifest(yaml.as_bytes()).unwrap();
        if limit == 1_048_576 {
            prop_assert_eq!(policy_digest(&a).unwrap(), policy_digest(&b).unwrap());
        } else {
            prop_assert_ne!(policy_digest(&a).unwrap(), policy_digest(&b).unwrap());
        }
    }
}
