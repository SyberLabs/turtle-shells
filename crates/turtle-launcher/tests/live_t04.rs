//! Live T04/T05/T07 against gVisor. Skips unless TURTLE_LIVE_SANDBOX=1 on a certified host.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use turtle_launcher::compile_launch_plan;
use turtle_launcher::gvisor::{self, GvisorBackend};
use turtle_launcher::oci::SandboxRequest;
use turtle_launcher::probe_host;
use turtle_launcher::SandboxBackend;
use turtle_policy::parse_manifest;

const WORKER: &[u8] = include_bytes!("../../../tests/fixtures/valid/read-only-repo-worker.yaml");
const PROBE: &str = include_str!("../../../tests/fixtures/runtime/t04-t05-t07.sh");

fn live_enabled() -> bool {
    std::env::var("TURTLE_LIVE_SANDBOX").ok().as_deref() == Some("1") && probe_host().certified
}

fn start_canary() -> (u16, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let accepts_thread = accepts.clone();
    let stop_thread = stop.clone();
    thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            if let Ok((mut stream, _)) = listener.accept() {
                accepts_thread.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let mut buf = [0u8; 32];
                let _ = stream.read(&mut buf);
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    (port, accepts, stop)
}

#[test]
fn live_t04_t05_t07_guest_cannot_reach_host_or_internet() {
    if !live_enabled() {
        eprintln!("skip live T04/T05/T07: TURTLE_LIVE_SANDBOX=1 and certified runsc host required");
        return;
    }
    let busybox = ["/bin/busybox", "/usr/bin/busybox"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.is_file())
        .expect("busybox-static must be installed for live tests");
    let (port, accepts, stop) = start_canary();
    let policy = parse_manifest(WORKER).unwrap();
    let mut plan = compile_launch_plan(&policy).unwrap();
    let canary = format!("http://127.0.0.1:{port}/");
    plan.argv = vec![
        "/bin/busybox".to_string(),
        "sh".to_string(),
        "/t04-t05-t07.sh".to_string(),
        canary,
    ];
    plan.cwd = "/".to_string();
    let root = std::env::temp_dir().join(format!("turtle-live-{}", std::process::id()));
    let bundle = root.join("bundle");
    let rootfs = root.join("rootfs");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    std::fs::copy(&busybox, rootfs.join("bin/busybox")).unwrap();
    std::fs::write(rootfs.join("t04-t05-t07.sh"), PROBE).unwrap();
    let frozen = GvisorBackend
        .create_frozen(&SandboxRequest {
            plan: &plan,
            bundle_dir: &bundle,
            rootfs: &rootfs,
        })
        .expect("frozen sandbox");
    assert!(frozen.inspected);
    let start = gvisor::start(&frozen);
    let code = if start.is_ok() {
        gvisor::wait(&frozen).unwrap_or(1)
    } else {
        1
    };
    let _ = gvisor::delete(&frozen);
    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(50));
    assert!(start.is_ok(), "{start:?}");
    assert_eq!(code, 0, "guest probe must exit 0 when attacks fail");
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "host canary must not observe a guest connection"
    );
}
