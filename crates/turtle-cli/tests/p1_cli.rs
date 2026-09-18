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
fn doctor_fails_closed_on_uncertified_host() {
    let output = Command::new(bin()).arg("doctor").output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tested backend assumptions"));
    assert!(stdout.contains("certified=false") || stdout.contains("openat2=false"));
    assert!(!stdout.to_lowercase().contains("status=enforced"));
}

#[test]
fn run_refuses_uncertified_host() {
    let output = Command::new(bin())
        .args([
            "run",
            "--manifest",
            fixture("tests/fixtures/valid/read-only-repo-worker.yaml")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("E_UNSUPPORTED_ENFORCEMENT"));
    let combined = format!("{stderr}{}", String::from_utf8_lossy(&output.stdout));
    assert!(!combined.to_lowercase().contains("status=enforced"));
}

#[test]
fn snapshot_import_fails_closed_without_openat2() {
    if turtle_snapshot::openat2_available() {
        return;
    }
    let output = Command::new(bin())
        .args([
            "snapshot",
            "import",
            "--from",
            fixture("tests/fixtures/valid").to_str().unwrap(),
            "--into",
            fixture("target").to_str().unwrap(),
            "--select",
            "read-only-repo-worker.yaml",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("E_UNSUPPORTED_ENFORCEMENT"));
}
