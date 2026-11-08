//! Capabilities and privilege drops (entrypoint.py's capset/su-exec logic).
//!
//! 3.0 runs no su-exec: children are started with setgroups/setgid/setuid
//! applied between fork and exec (std's Command uid/gid), and the result is
//! then read back from /proc before anything is trusted with the key.

use crate::py;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
/// What the supervisor keeps after setup: DAC_OVERRIDE to publish addresses
/// inside the tor-owned DataDirectory, SETUID/SETGID to start tor-user children.
pub const POST_SETUP_CAPS: u64 = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_SETGID) | (1 << CAP_SETUID);

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn cap_name(bit: u32) -> String {
    match bit {
        CAP_CHOWN => "CHOWN".into(),
        CAP_DAC_OVERRIDE => "DAC_OVERRIDE".into(),
        CAP_FOWNER => "FOWNER".into(),
        CAP_SETGID => "SETGID".into(),
        CAP_SETUID => "SETUID".into(),
        b => format!("bit {b}"),
    }
}

pub fn permitted_capabilities() -> Option<u64> {
    let mut h = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapData::default(); 2];
    // SAFETY: capget with a v3 header and two data structs, as the ABI requires.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut CapHeader, d.as_mut_ptr()) };
    (rc == 0).then(|| u64::from(d[0].permitted) | (u64::from(d[1].permitted) << 32))
}

/// The capabilities `mask` asks for that `held` does not have, by name.
fn missing_caps(mask: u64, held: u64) -> Vec<String> {
    (0..64)
        .filter(|b| (mask >> b) & 1 == 1 && (held >> b) & 1 == 0)
        .map(cap_name)
        .collect()
}

/// _drop_setup_capabilities: narrow effective+permitted to `mask & held`, for good.
/// The two 32-bit halves capset(2) v3 takes: capabilities 0-31, then 32-63.
/// Both are set, so the "retains" line logged afterwards is exactly what was kept.
fn cap_data(mask: u64) -> [CapData; 2] {
    let half = |bits: u64| CapData {
        effective: bits as u32,
        permitted: bits as u32,
        inheritable: 0,
    };
    [half(mask & 0xFFFF_FFFF), half(mask >> 32)]
}

pub fn drop_setup_capabilities(mask: u64, log: &mut Vec<String>) -> bool {
    let mut mask = mask;
    if let Some(held) = permitted_capabilities() {
        let wanted = mask & held;
        if wanted != mask {
            let missing = missing_caps(mask, held);
            log.push(format!(
                "Note: this runtime did not grant {}; dropping everything else regardless.",
                missing.join(", ")
            ));
        }
        mask = wanted;
    }
    let mut h = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let d = cap_data(mask);
    // SAFETY: capset with a v3 header and two data structs.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, d.as_ptr()) };
    if rc != 0 {
        log.push(format!(
            "Warning: could not drop setup capabilities: {}. Continuing with the capabilities the runtime granted.",
            py::strerror(py::last_errno())
        ));
        return false;
    }
    let kept: Vec<String> = (0..64)
        .filter(|b| (mask >> b) & 1 == 1)
        .map(cap_name)
        .collect();
    let kept = if kept.is_empty() {
        "nothing".to_string()
    } else {
        kept.join(", ")
    };
    log.push(format!(
        "Dropped setup capabilities; supervisor retains 0x{mask:02x} ({kept})."
    ));
    true
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// The tor user as children must run. None = start children as we are (no-root mode).
#[derive(Clone, Copy, Debug)]
pub struct AsUser {
    pub uid: u32,
    pub gid: u32,
}

pub fn self_exe() -> String {
    std::fs::read_link("/proc/self/exe")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/usr/local/bin/hiddenforge".to_string())
}

/// A command that runs as `user` (when root) with HOME set the way su-exec set it.
pub fn command(
    program: &str,
    argv0: Option<&str>,
    args: &[&str],
    user: Option<AsUser>,
    home: &str,
) -> Command {
    let mut c = Command::new(program);
    if let Some(a0) = argv0 {
        c.arg0(a0);
    }
    c.args(args);
    if let Some(u) = user {
        // std drops supplementary groups (setgroups(0)) before setgid/setuid.
        c.uid(u.uid).gid(u.gid);
        c.env("HOME", home);
    }
    c
}

/// Run a command with a deadline; returns (exit code or None on timeout/kill, stdout, stderr).
pub fn run_timeout(
    c: Command,
    timeout: Duration,
) -> std::io::Result<(Option<i32>, Vec<u8>, Vec<u8>)> {
    run_piped(c, None, timeout)
}

/// Run a command with `input` on its stdin (a pipe, never argv or the
/// environment) and a deadline; returns (exit code, stdout, stderr).
pub fn run_with_input(
    c: Command,
    input: &[u8],
    timeout: Duration,
) -> std::io::Result<(Option<i32>, Vec<u8>, Vec<u8>)> {
    run_piped(c, Some(input), timeout)
}

/// How long the output readers may outlive the child: a grandchild that inherited
/// stdout or stderr keeps the pipe open after the child itself has gone.
const PIPE_GRACE: Duration = Duration::from_secs(2);

fn run_piped(
    mut c: Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<(Option<i32>, Vec<u8>, Vec<u8>)> {
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::sync::{mpsc, Arc, Mutex};
    c.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = c.spawn()?;
    let deadline = Instant::now() + timeout;
    let (done_tx, done_rx) = mpsc::channel::<()>();
    // Readers first, then the writer, each on its own thread: a child that writes
    // before it reads can never deadlock against us, and the deadline covers the
    // write as well. Readers fill shared buffers so a reader still blocked on a
    // grandchild's pipe can be abandoned with what it has read so far.
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let (b, tx) = (Arc::clone(&buf), done_tx.clone());
        std::thread::spawn(move || {
            if let Some(mut p) = pipe {
                let mut chunk = [0u8; 8192];
                while let Ok(n @ 1..) = p.read(&mut chunk) {
                    b.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .extend_from_slice(&chunk[..n]);
                }
            }
            let _ = tx.send(());
        });
        buf
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    drop(done_tx);
    if let (Some(mut si), Some(data)) = (child.stdin.take(), input) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
    }
    let code = loop {
        if let Some(st) = child.try_wait()? {
            break st.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let grace = Instant::now() + PIPE_GRACE;
    for _ in 0..2 {
        let left = grace.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    let take =
        |b: Arc<Mutex<Vec<u8>>>| std::mem::take(&mut *b.lock().unwrap_or_else(|e| e.into_inner()));
    Ok((code, take(out), take(err)))
}

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .map(str::trim)
}

pub fn uid_from_status(status: &str) -> Option<u32> {
    status_field(status, "Uid:")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// _assert_process_dropped: refuse to continue if the child still runs as root.
pub fn assert_process_dropped(child: &Child, name: &str, log: &mut Vec<String>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = child.id();
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            match uid_from_status(&s) {
                Some(0) => {
                    log.push(format!(
                        "FATAL: {name} (pid {pid}) is running as root; the privilege drop to the tor user failed. Refusing to continue."
                    ));
                    return false;
                }
                Some(_) => return true,
                None => {}
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    log.push(format!(
        "FATAL: could not confirm {name} dropped privileges within 5s."
    ));
    false
}

/// Send `sig` to `pid`; true if delivered. The supervisor is root but holds no
/// CAP_KILL (no compose file grants it), so it cannot signal the tor-owned
/// children itself: when that is refused, `as_owner` delivers it from a
/// process running as the children's own user.
pub fn signal(pid: u32, sig: i32, as_owner: &dyn Fn(u32, i32) -> bool) -> bool {
    // SAFETY: kill(2) on a pid we started.
    if unsafe { libc::kill(pid as i32, sig) } == 0 {
        return true;
    }
    py::last_errno() == libc::EPERM && as_owner(pid, sig)
}

/// _kill_proc: SIGTERM (SIGINT for Tor), wait up to `timeout`, then SIGKILL. Never blocks for ever.
pub fn kill_proc(
    child: &mut Option<Child>,
    name: &str,
    timeout: Duration,
    as_owner: &dyn Fn(u32, i32) -> bool,
) {
    let Some(c) = child.as_mut() else { return };
    if c.try_wait().ok().flatten().is_some() {
        return;
    }
    let pid = c.id();
    // Tor blocks SIGTERM in practice and exits cleanly on SIGINT ("Interrupt:
    // exiting cleanly", measured ~2 s); everything else here takes SIGTERM.
    let first = if name == "Tor" {
        libc::SIGINT
    } else {
        libc::SIGTERM
    };
    signal(pid, first, as_owner);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if c.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("{name} did not stop in time, killing...");
    signal(pid, libc::SIGKILL, as_owner);
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if c.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Still there: leave it. PID 1 exiting next takes the whole namespace down.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_data_splits_the_mask_into_both_halves() {
        let d = cap_data((1 << 40) | (1 << CAP_SETUID));
        assert_eq!(
            (d[0].effective, d[0].permitted, d[0].inheritable),
            (1 << 7, 1 << 7, 0)
        );
        assert_eq!(
            (d[1].effective, d[1].permitted, d[1].inheritable),
            (1 << 8, 1 << 8, 0)
        );
        let z = cap_data(0);
        assert_eq!((z[0].permitted, z[1].permitted), (0, 0));
    }

    #[test]
    fn run_piped_survives_a_child_that_writes_before_it_reads() {
        // 1 MB in, 1 MB out before reading any of it: writing all the input
        // before starting the readers deadlocks both sides on full pipes.
        let mut c = Command::new("sh");
        c.args([
            "-c",
            "head -c 1000000 /dev/zero; cat >/dev/null; echo done >&2",
        ]);
        let (code, out, err) =
            run_with_input(c, &vec![0u8; 1_000_000], Duration::from_secs(20)).unwrap();
        assert_eq!(
            (code, out.len(), err.as_slice()),
            (Some(0), 1_000_000, &b"done\n"[..])
        );
    }

    #[test]
    fn run_piped_does_not_wait_for_a_grandchild_holding_the_pipe() {
        let mut c = Command::new("sh");
        c.args(["-c", "sleep 8 & echo hi"]);
        let started = Instant::now();
        let (code, out, _) = run_timeout(c, Duration::from_secs(20)).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "{:?}",
            started.elapsed()
        );
        assert_eq!((code, out.as_slice()), (Some(0), &b"hi\n"[..]));
    }

    #[test]
    fn run_piped_kills_at_the_deadline() {
        let mut c = Command::new("sleep");
        c.arg("30");
        let started = Instant::now();
        let (code, _, _) = run_timeout(c, Duration::from_millis(300)).unwrap();
        assert_eq!(code, None);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn parses_uid() {
        assert_eq!(
            uid_from_status("Name:\ttor\nUid:\t100\t100\t100\t100\n"),
            Some(100)
        );
        assert_eq!(uid_from_status("Name:\tx\n"), None);
    }

    #[test]
    fn reads_own_caps() {
        assert!(permitted_capabilities().is_some());
    }
}
