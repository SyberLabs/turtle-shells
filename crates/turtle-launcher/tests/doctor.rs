use turtle_launcher::{probe_host, P1_CLAIM_CEILING};

#[test]
fn uncertified_host_is_not_certified() {
    let probe = probe_host();
    if cfg!(not(target_os = "linux")) {
        assert!(!probe.certified);
        assert!(!probe.openat2);
        assert!(probe.runsc.is_none());
        assert!(!probe.failures.is_empty());
    }
    assert!(P1_CLAIM_CEILING.contains("tested backend assumptions"));
}
