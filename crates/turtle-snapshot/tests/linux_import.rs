#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use turtle_policy::path::RelPath;
use turtle_snapshot::{export_patch, import_snapshot, ExportRequest, ImportRequest};

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("turtle-linux-{}-{}", label, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn import_copies_selected_file_only() {
    let src = scratch("src");
    fs::create_dir_all(src.join("src")).unwrap();
    fs::write(src.join("src/a.txt"), b"hello").unwrap();
    fs::write(src.join("secret.txt"), b"nope").unwrap();
    let dest = scratch("dest");
    let selected = [RelPath::parse("src/a.txt").unwrap()];
    import_snapshot(&ImportRequest {
        source_root: &src,
        selected: &selected,
        dest_root: &dest,
    })
    .unwrap();
    assert_eq!(fs::read(dest.join("src/a.txt")).unwrap(), b"hello");
    assert!(!dest.join("secret.txt").exists());
}

#[test]
fn import_rejects_symlink_and_leaves_host_sentinel() {
    let src = scratch("src-link");
    let sentinel = scratch("sentinel");
    let sentinel_file = sentinel.join("host.txt");
    fs::write(&sentinel_file, b"untouched").unwrap();
    std::os::unix::fs::symlink(&sentinel_file, src.join("escape")).unwrap();
    let dest = scratch("dest-link");
    let selected = [RelPath::parse("escape").unwrap()];
    let err = import_snapshot(&ImportRequest {
        source_root: &src,
        selected: &selected,
        dest_root: &dest,
    })
    .unwrap_err();
    assert!(err.to_string().contains("openat2") || err.to_string().contains("regular"));
    assert_eq!(fs::read(&sentinel_file).unwrap(), b"untouched");
    assert!(!dest.join("escape").exists());
}

#[test]
fn import_rejects_git_config_even_if_selected() {
    let src = scratch("src-git");
    fs::create_dir_all(src.join(".git")).unwrap();
    fs::write(src.join(".git/config"), b"bad").unwrap();
    let dest = scratch("dest-git");
    let selected = [RelPath::parse(".git/config").unwrap()];
    assert!(import_snapshot(&ImportRequest {
        source_root: &src,
        selected: &selected,
        dest_root: &dest,
    })
    .is_err());
}

#[test]
fn export_includes_modified_files_under_subtree_only() {
    let snap = scratch("snap");
    let work = scratch("work");
    fs::create_dir_all(snap.join("src")).unwrap();
    fs::create_dir_all(work.join("src")).unwrap();
    fs::write(snap.join("src/a.txt"), b"old").unwrap();
    fs::write(work.join("src/a.txt"), b"new").unwrap();
    fs::write(work.join("outside.txt"), b"nope").unwrap();
    let subtrees = [RelPath::parse("src").unwrap()];
    let artifact = export_patch(&ExportRequest {
        snapshot_root: &snap,
        work_root: &work,
        export_subtrees: &subtrees,
    })
    .unwrap();
    assert!(artifact.files.iter().any(|f| f.path == "src/a.txt"));
    assert!(artifact.files.iter().all(|f| f.path != "outside.txt"));
}

#[test]
fn export_rejects_executable_mode() {
    let snap = scratch("snap-exec");
    let work = scratch("work-exec");
    fs::write(work.join("run.sh"), b"echo hi").unwrap();
    let mut perms = fs::metadata(work.join("run.sh")).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(work.join("run.sh"), perms).unwrap();
    let subtrees = [RelPath::parse("run.sh").unwrap()];
    assert!(export_patch(&ExportRequest {
        snapshot_root: &snap,
        work_root: &work,
        export_subtrees: &subtrees,
    })
    .is_err());
}
