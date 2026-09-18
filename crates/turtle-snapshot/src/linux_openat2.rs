//! Isolated Linux `openat2` helpers.
//!
//! Safety: every public function takes a trusted directory fd or owner-supplied
//! root path and a relative child name that must not contain `/` or NUL.
//! Flags always include `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use turtle_policy::PolicyError;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

const RESOLVE_FLAGS: u64 =
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub fn available() -> bool {
    open_trusted_dir(Path::new(".")).is_ok()
}

pub fn open_trusted_dir(path: &Path) -> Result<OwnedFd, PolicyError> {
    let c = path_c(path)?;
    // SAFETY: `c` is a valid CString; open flags request a directory and refuse
    // a final symlink. The caller supplies a trusted owner path.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_from_raw(fd, "open trusted directory")
}

pub fn open_beneath(
    dir: &OwnedFd,
    name: &str,
    flags: i32,
    mode: u64,
) -> Result<OwnedFd, PolicyError> {
    if name.is_empty() || name.contains('/') || name.contains('\0') || name == "." || name == ".." {
        return Err(PolicyError::schema(format!(
            "refusing openat2 name `{name}`"
        )));
    }
    let c = CString::new(name).map_err(|_| PolicyError::schema("path contains NUL"))?;
    let how = OpenHow {
        flags: flags as u64,
        mode,
        resolve: RESOLVE_FLAGS,
    };
    // SAFETY: `dir` is an open fd, `c` is a single-segment name, `how` is a
    // well-formed open_how with beneath/no-symlink resolve flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    owned_from_raw(fd as RawFd, "openat2")
}

pub fn mkdir_beneath(dir: &OwnedFd, name: &str) -> Result<(), PolicyError> {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return Err(PolicyError::schema("invalid mkdir name"));
    }
    let c = CString::new(name).map_err(|_| PolicyError::schema("path contains NUL"))?;
    // SAFETY: directory fd is valid; name is a single path segment.
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) };
    if rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(PolicyError::unsupported(format!(
            "mkdirat `{name}`: {}",
            std::io::Error::last_os_error()
        )))
    }
}

pub fn fstat(fd: &OwnedFd) -> Result<libc::stat, PolicyError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is valid; st is a writable stat buffer.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    if rc == 0 {
        Ok(st)
    } else {
        Err(PolicyError::unsupported(format!(
            "fstat: {}",
            std::io::Error::last_os_error()
        )))
    }
}

pub fn read_dir_names(dir: &OwnedFd) -> Result<Vec<String>, PolicyError> {
    let dup = dup_fd(dir)?;
    let raw = dup.as_raw_fd();
    // SAFETY: fdopendir takes ownership of `raw`. `dup` must not drop the fd.
    std::mem::forget(dup);
    let dirp = unsafe { libc::fdopendir(raw) };
    if dirp.is_null() {
        return Err(PolicyError::unsupported("fdopendir failed"));
    }
    let mut names = Vec::new();
    loop {
        errno_clear();
        // SAFETY: dirp came from fdopendir and is not closed yet.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is a NUL-terminated kernel string.
        let cstr = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let name = OsStr::from_bytes(cstr.to_bytes())
            .to_str()
            .ok_or_else(|| PolicyError::schema("directory entry is not UTF-8"))?
            .to_string();
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    // SAFETY: dirp is a live DIR* we own.
    unsafe {
        libc::closedir(dirp);
    }
    Ok(names)
}

fn dup_fd(fd: &OwnedFd) -> Result<OwnedFd, PolicyError> {
    let n = unsafe { libc::dup(fd.as_raw_fd()) };
    owned_from_raw(n, "dup")
}

fn owned_from_raw(fd: RawFd, what: &str) -> Result<OwnedFd, PolicyError> {
    if fd < 0 {
        Err(PolicyError::unsupported(format!(
            "{what}: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        // SAFETY: fd is a newly opened descriptor we now own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn path_c(path: &Path) -> Result<CString, PolicyError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| PolicyError::schema("path contains NUL"))
}

fn errno_clear() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}
