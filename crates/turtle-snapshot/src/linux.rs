//! Linux snapshot copy using `openat2`.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use turtle_policy::path::RelPath;
use turtle_policy::PolicyError;

use crate::artifact::{ExportArtifact, ExportFile};
use crate::classify::{classify_relative_path, is_excluded_name};
use crate::export::ExportRequest;
use crate::import::{ImportRequest, Snapshot};
use sha2::{Digest, Sha256};

use crate::linux_openat2;

pub fn openat2_available() -> bool {
    linux_openat2::available()
}

pub fn import_snapshot(request: &ImportRequest<'_>) -> Result<Snapshot, PolicyError> {
    if request.selected.is_empty() {
        return Err(PolicyError::schema("import selection is empty"));
    }
    std::fs::create_dir_all(request.dest_root)
        .map_err(|e| PolicyError::unsupported(format!("create snapshot dest: {e}")))?;
    let src = linux_openat2::open_trusted_dir(request.source_root)?;
    let dest = linux_openat2::open_trusted_dir(request.dest_root)?;
    let mut files = Vec::new();
    for rel in request.selected {
        classify_relative_path(&rel.to_string())?;
        import_path(&src, &dest, rel.segments(), &mut files)?;
    }
    Ok(Snapshot {
        dest_root: PathBuf::from(request.dest_root),
        files,
    })
}

pub fn export_patch(request: &ExportRequest<'_>) -> Result<ExportArtifact, PolicyError> {
    let work = linux_openat2::open_trusted_dir(request.work_root)?;
    let snap = linux_openat2::open_trusted_dir(request.snapshot_root).ok();
    let mut files = Vec::new();
    for rel in request.export_subtrees {
        classify_relative_path(&rel.to_string())?;
        export_path(&work, snap.as_ref(), rel.segments(), &mut files)?;
    }
    Ok(ExportArtifact {
        policy_digest: None,
        files,
    })
}

fn import_path(
    src_root: &OwnedFd,
    dest_root: &OwnedFd,
    segments: &[String],
    files: &mut Vec<RelPath>,
) -> Result<(), PolicyError> {
    let src = open_segments(src_root, segments, libc::O_RDONLY | libc::O_CLOEXEC)?;
    let st = linux_openat2::fstat(&src)?;
    if is_dir(&st) {
        let dest = ensure_dir_segments(dest_root, segments)?;
        import_tree(&src, &dest, segments, files)?;
    } else if is_reg(&st) {
        reject_hardlink(&st)?;
        let dest_parent = if segments.len() == 1 {
            dest_root
                .try_clone()
                .map_err(|e| PolicyError::unsupported(e.to_string()))?
        } else {
            ensure_dir_segments(dest_root, &segments[..segments.len() - 1])?
        };
        copy_file(&src, &dest_parent, segments.last().expect("file name"))?;
        files.push(rel_from(segments)?);
    } else {
        return Err(PolicyError::unsupported(
            "snapshot import accepts regular files and directories only",
        ));
    }
    Ok(())
}

fn import_tree(
    src_dir: &OwnedFd,
    dest_dir: &OwnedFd,
    prefix: &[String],
    files: &mut Vec<RelPath>,
) -> Result<(), PolicyError> {
    for name in linux_openat2::read_dir_names(src_dir)? {
        if is_excluded_name(&name) {
            continue;
        }
        let child_src =
            linux_openat2::open_beneath(src_dir, &name, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
        let st = linux_openat2::fstat(&child_src)?;
        let mut child_path = prefix.to_vec();
        child_path.push(name.clone());
        if is_dir(&st) {
            linux_openat2::mkdir_beneath(dest_dir, &name)?;
            let child_dest = linux_openat2::open_beneath(
                dest_dir,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
            )?;
            import_tree(&child_src, &child_dest, &child_path, files)?;
        } else if is_reg(&st) {
            reject_hardlink(&st)?;
            copy_file(&child_src, dest_dir, &name)?;
            files.push(rel_from(&child_path)?);
        } else {
            return Err(PolicyError::unsupported(format!(
                "`{}` is not a regular file or directory",
                child_path.join("/")
            )));
        }
    }
    Ok(())
}

fn export_path(
    work_root: &OwnedFd,
    snap_root: Option<&OwnedFd>,
    segments: &[String],
    out: &mut Vec<ExportFile>,
) -> Result<(), PolicyError> {
    let work = match open_segments(work_root, segments, libc::O_RDONLY | libc::O_CLOEXEC) {
        Ok(fd) => fd,
        Err(_) => {
            out.push(ExportFile {
                path: segments.join("/"),
                sha256: String::new(),
                mode: 0,
                deleted: true,
            });
            return Ok(());
        }
    };
    let st = linux_openat2::fstat(&work)?;
    if is_dir(&st) {
        for name in linux_openat2::read_dir_names(&work)? {
            if is_excluded_name(&name) {
                continue;
            }
            let mut child = segments.to_vec();
            child.push(name);
            export_path(work_root, snap_root, &child, out)?;
        }
        return Ok(());
    }
    if !is_reg(&st) {
        return Err(PolicyError::unsupported(
            "export accepts regular files only",
        ));
    }
    let mode = st.st_mode & 0o777;
    if mode & 0o111 != 0 {
        return Err(PolicyError::unsupported(
            "first worker template rejects executable export modes",
        ));
    }
    let bytes = read_all(&work)?;
    if let Some(snap) = snap_root {
        if let Ok(old) = open_segments(snap, segments, libc::O_RDONLY | libc::O_CLOEXEC) {
            if read_all(&old)? == bytes {
                return Ok(());
            }
        }
    }
    out.push(ExportFile {
        path: segments.join("/"),
        sha256: hex::encode(Sha256::digest(&bytes)),
        mode,
        deleted: false,
    });
    Ok(())
}

fn open_segments(root: &OwnedFd, segments: &[String], flags: i32) -> Result<OwnedFd, PolicyError> {
    let mut cur = root
        .try_clone()
        .map_err(|e| PolicyError::unsupported(e.to_string()))?;
    for (i, name) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        let f = if last {
            flags
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
        };
        cur = linux_openat2::open_beneath(&cur, name, f, 0)?;
    }
    Ok(cur)
}

fn ensure_dir_segments(root: &OwnedFd, segments: &[String]) -> Result<OwnedFd, PolicyError> {
    let mut cur = root
        .try_clone()
        .map_err(|e| PolicyError::unsupported(e.to_string()))?;
    for name in segments {
        linux_openat2::mkdir_beneath(&cur, name)?;
        cur = linux_openat2::open_beneath(
            &cur,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
    }
    Ok(cur)
}

fn copy_file(src: &OwnedFd, dest_dir: &OwnedFd, name: &str) -> Result<(), PolicyError> {
    let bytes = read_all(src)?;
    let created = linux_openat2::open_beneath(
        dest_dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o644,
    )?;
    let mut file = std::fs::File::from(created);
    file.write_all(&bytes)
        .map_err(|e| PolicyError::unsupported(format!("write snapshot file: {e}")))?;
    Ok(())
}

fn read_all(fd: &OwnedFd) -> Result<Vec<u8>, PolicyError> {
    let cloned = fd
        .try_clone()
        .map_err(|e| PolicyError::unsupported(e.to_string()))?;
    let mut file = std::fs::File::from(cloned);
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| PolicyError::unsupported(format!("read snapshot file: {e}")))?;
    Ok(buf)
}

fn is_reg(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn reject_hardlink(st: &libc::stat) -> Result<(), PolicyError> {
    if st.st_nlink > 1 {
        Err(PolicyError::unsupported(
            "hard-linked files cannot be imported",
        ))
    } else {
        Ok(())
    }
}

fn rel_from(segments: &[String]) -> Result<RelPath, PolicyError> {
    RelPath::parse(&segments.join("/"))
}
