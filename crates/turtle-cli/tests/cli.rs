//! CLI contract tests for `turtle policy check|explain|diff`.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_turtle"))
}

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

#[test]
fn check_valid_exits_zero() {
    let output = Command::new(bin())
        .args([
            "policy",
            "check",
            fixture("tests/fixtures/valid/read-only-repo-worker.yaml")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("digest="));
    assert!(stdout.contains("No containment claim"));
}

#[test]
fn check_invalid_exits_one() {
    let output = Command::new(bin())
        .args([
            "policy",
            "check",
            fixture("tests/fixtures/malformed/unknown-field.yaml")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("E_SCHEMA"));
}

#[test]
fn explain_labels_p0_limitations() {
    let output = Command::new(bin())
        .args([
            "policy",
            "explain",
            fixture("tests/fixtures/valid/read-only-repo-worker.yaml")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("not deployed in P0"));
    assert!(stdout.contains("No containment claim"));
    assert!(!stdout.to_lowercase().contains("status=enforced"));
}

#[test]
fn diff_json_widening_exits_two() {
    let output = Command::new(bin())
        .args([
            "policy",
            "diff",
            "--format",
            "json",
            fixture("tests/fixtures/diff/old.yaml").to_str().unwrap(),
            fixture("tests/fixtures/diff/widen.yaml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("widening"));
}
