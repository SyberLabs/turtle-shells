use std::fs;
use std::path::PathBuf;

use turtle_policy::path::RelPath;
use turtle_policy::ReasonCode;
use turtle_snapshot::{export_patch, import_snapshot, ExportRequest, ImportRequest};

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "turtle-p1-{}-{}-{}",
        label,
        std::process::id(),
        label.len()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn import_without_openat2_does_not_copy() {
    let src = scratch("import-src");
    fs::write(src.join("a.txt"), b"hello").unwrap();
    let dest = scratch("import-dest").join("snap");
    let selected = [RelPath::parse("a.txt").unwrap()];
    let err = import_snapshot(&ImportRequest {
        source_root: &src,
        selected: &selected,
        dest_root: &dest,
    })
    .expect_err("uncertified import must fail");
    assert_eq!(err.reason_code(), ReasonCode::EUnsupportedEnforcement);
    assert!(!dest.join("a.txt").exists());
}

#[test]
fn export_without_openat2_does_not_emit_files() {
    let snap = scratch("export-snap");
    let work = scratch("export-work");
    fs::write(work.join("a.txt"), b"changed").unwrap();
    let subtrees = [RelPath::parse("a.txt").unwrap()];
    let err = export_patch(&ExportRequest {
        snapshot_root: &snap,
        work_root: &work,
        export_subtrees: &subtrees,
    })
    .expect_err("uncertified export must fail");
    assert_eq!(err.reason_code(), ReasonCode::EUnsupportedEnforcement);
}
