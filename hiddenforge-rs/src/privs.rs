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

/// What to ask capset for, given the permitted set the runtime granted: the
/// mask narrowed to `held` (capset refuses a request that is not a subset), and
/// the note to log when something was not granted.
fn plan_drop(mask: u64, held: Option<u64>) -> (u64, Option<String>) {
    let Some(held) = held else {
        return (mask, None);
    };
    let wanted = mask & held;
    let note = (wanted != mask).then(|| {
        format!(
            "Note: this runtime did not grant {}; dropping everything else regardless.",
            missing_caps(mask, held).join(", ")
        )
    });
    (wanted, note)
}

/// The line logged once the drop worked: what the supervisor kept.
fn retained_summary(mask: u64) -> String {
    let kept: Vec<String> = (0..64)
        .filter(|b| (mask >> b) & 1 == 1)
        .map(cap_name)
        .collect();
    let kept = if kept.is_empty() {
        "nothing".to_string()
    } else {
        kept.join(", ")
    };
    format!("Dropped setup capabilities; supervisor retains 0x{mask:02x} ({kept}).")
}

pub fn drop_setup_capabilities(mask: u64, log: &mut Vec<String>) -> bool {
    let (mask, note) = plan_drop(mask, permitted_capabilities());
    log.extend(note);
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
    log.push(retained_summary(mask));
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

/// Some(true) = the process runs as a non-root user, Some(false) = as root,
/// None = the status text has no readable Uid line yet.
fn drop_verdict(status: &str) -> Option<bool> {
    uid_from_status(status).map(|uid| uid != 0)
}

/// _assert_process_dropped: refuse to continue if the child still runs as root.
pub fn assert_process_dropped(child: &Child, name: &str, log: &mut Vec<String>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = child.id();
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            match drop_verdict(&s) {
                Some(true) => return true,
                Some(false) => {
                    log.push(format!(
                        "FATAL: {name} (pid {pid}) is running as root; the privilege drop to the tor user failed. Refusing to continue."
                    ));
                    return false;
                }
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
    signal_via(
        |pid, sig|
        // SAFETY: kill(2) on a pid we started.
        if unsafe { libc::kill(pid as i32, sig) } == 0 { Ok(()) } else { Err(py::last_errno()) },
        pid,
        sig,
        as_owner,
    )
}

/// `signal` with the kill(2) call injected: Err carries the errno.
fn signal_via(
    kill: impl Fn(u32, i32) -> Result<(), i32>,
    pid: u32,
    sig: i32,
    as_owner: &dyn Fn(u32, i32) -> bool,
) -> bool {
    match kill(pid, sig) {
        Ok(()) => true,
        Err(e) => e == libc::EPERM && as_owner(pid, sig),
    }
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
    fn permitted_capabilities_matches_the_kernel_status_line() {
        // capget(pid 0) is per thread, so compare with this thread's status.
        let st = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let hex = status_field(&st, "CapPrm:").unwrap();
        assert_eq!(
            permitted_capabilities(),
            Some(u64::from_str_radix(hex, 16).unwrap())
        );
    }

    #[test]
    fn cap_names_and_the_post_setup_mask() {
        for (bit, name) in [
            (CAP_CHOWN, "CHOWN"),
            (CAP_DAC_OVERRIDE, "DAC_OVERRIDE"),
            (CAP_FOWNER, "FOWNER"),
            (CAP_SETGID, "SETGID"),
            (CAP_SETUID, "SETUID"),
            (2, "bit 2"),
            (63, "bit 63"),
        ] {
            assert_eq!(cap_name(bit), name);
        }
        assert_eq!(
            [
                CAP_CHOWN,
                CAP_DAC_OVERRIDE,
                CAP_FOWNER,
                CAP_SETGID,
                CAP_SETUID
            ],
            [0, 1, 3, 6, 7]
        );
        assert_eq!(POST_SETUP_CAPS, 0xC2);
    }

    #[test]
    fn missing_caps_lists_requested_but_not_held_in_bit_order() {
        let all = POST_SETUP_CAPS;
        assert_eq!(missing_caps(all, 0), ["DAC_OVERRIDE", "SETGID", "SETUID"]);
        assert_eq!(missing_caps(all, all), Vec::<String>::new());
        assert_eq!(
            missing_caps(all, 1 << CAP_SETGID),
            ["DAC_OVERRIDE", "SETUID"]
        );
        // held but not requested is not missing; bits >= 32 are looked at too
        assert_eq!(missing_caps(1 | (1 << 40), 1 << 1), ["CHOWN", "bit 40"]);
        assert_eq!(missing_caps(0, 0), Vec::<String>::new());
    }

    #[test]
    fn plan_drop_narrows_to_what_is_held_and_says_so() {
        // capget failed: ask for the mask as given, no note
        assert_eq!(plan_drop(POST_SETUP_CAPS, None), (POST_SETUP_CAPS, None));
        // everything held: unchanged, no note
        assert_eq!(
            plan_drop(POST_SETUP_CAPS, Some(u64::MAX)),
            (POST_SETUP_CAPS, None)
        );
        // nothing held: the entrypoint.py wording, names in bit order
        assert_eq!(
            plan_drop(POST_SETUP_CAPS, Some(0)),
            (
                0,
                Some(
                    "Note: this runtime did not grant DAC_OVERRIDE, SETGID, SETUID; dropping everything else regardless."
                        .to_string()
                )
            )
        );
        // partly held: the intersection, and only the missing ones named
        let held = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_CHOWN);
        assert_eq!(
            plan_drop(POST_SETUP_CAPS, Some(held)),
            (
                1 << CAP_DAC_OVERRIDE,
                Some(
                    "Note: this runtime did not grant SETGID, SETUID; dropping everything else regardless."
                        .to_string()
                )
            )
        );
    }

    #[test]
    fn retained_summary_matches_entrypoint_py() {
        assert_eq!(
            retained_summary(POST_SETUP_CAPS),
            "Dropped setup capabilities; supervisor retains 0xc2 (DAC_OVERRIDE, SETGID, SETUID)."
        );
        assert_eq!(
            retained_summary(0),
            "Dropped setup capabilities; supervisor retains 0x00 (nothing)."
        );
        assert_eq!(
            retained_summary(1),
            "Dropped setup capabilities; supervisor retains 0x01 (CHOWN)."
        );
        assert_eq!(
            retained_summary(1 << 40),
            "Dropped setup capabilities; supervisor retains 0x10000000000 (bit 40)."
        );
    }

    #[test]
    fn dropping_capabilities_for_real_leaves_exactly_the_planned_set() {
        if is_root() {
            return; // a root drop is environment-specific: covered by the live e2e test
        }
        // capset is per thread: do it on a thread of its own.
        let (log, ok, after, held) = std::thread::spawn(|| {
            let held = permitted_capabilities().unwrap();
            let mut log = Vec::new();
            let ok = drop_setup_capabilities(POST_SETUP_CAPS, &mut log);
            (log, ok, permitted_capabilities().unwrap(), held)
        })
        .join()
        .unwrap();
        let (want, note) = plan_drop(POST_SETUP_CAPS, Some(held));
        assert!(ok, "{log:?}");
        assert_eq!(after, want);
        let mut expect: Vec<String> = note.into_iter().collect();
        expect.push(retained_summary(want));
        assert_eq!(log, expect);
    }

    #[test]
    fn dropping_with_no_capabilities_held_logs_the_note_then_nothing() {
        if is_root() || permitted_capabilities() != Some(0) {
            return;
        }
        let log = std::thread::spawn(|| {
            let mut log = Vec::new();
            assert!(drop_setup_capabilities(POST_SETUP_CAPS, &mut log));
            log
        })
        .join()
        .unwrap();
        assert_eq!(
            log,
            [
                "Note: this runtime did not grant DAC_OVERRIDE, SETGID, SETUID; dropping everything else regardless.",
                "Dropped setup capabilities; supervisor retains 0x00 (nothing)."
            ]
        );
    }

    #[test]
    fn run_piped_returns_exit_code_and_each_stream_separately() {
        let mut c = Command::new("sh");
        c.args(["-c", "printf out; printf err >&2; exit 3"]);
        let (code, out, err) = run_timeout(c, Duration::from_secs(10)).unwrap();
        assert_eq!(
            (code, out.as_slice(), err.as_slice()),
            (Some(3), &b"out"[..], &b"err"[..])
        );
    }

    #[test]
    fn run_piped_without_input_gives_the_child_a_closed_stdin() {
        // cat on /dev/null stdin ends at once; on an open pipe it would hang to the deadline.
        let started = Instant::now();
        let (code, out, _) = run_timeout(Command::new("cat"), Duration::from_secs(10)).unwrap();
        assert_eq!((code, out.as_slice()), (Some(0), &b""[..]));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn run_with_input_delivers_the_bytes_and_closes_stdin() {
        let input = b"line one\nsecond \x00 line\n";
        let (code, out, err) =
            run_with_input(Command::new("cat"), input, Duration::from_secs(10)).unwrap();
        assert_eq!(
            (code, out.as_slice(), err.as_slice()),
            (Some(0), &input[..], &b""[..])
        );
    }

    #[test]
    fn run_piped_keeps_partial_output_of_a_child_killed_at_the_deadline() {
        let mut c = Command::new("sh");
        c.args(["-c", "printf partial; exec sleep 100"]);
        let (code, out, _) = run_timeout(c, Duration::from_millis(500)).unwrap();
        assert_eq!((code, out.as_slice()), (None, &b"partial"[..]));
    }

    #[test]
    fn run_piped_reports_a_spawn_failure() {
        let e = run_timeout(
            Command::new("/nonexistent/definitely-not-here"),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn command_sets_argv0_args_and_only_sets_home_for_a_user() {
        let c = command(
            "sh",
            Some("renamed"),
            &["-c", "printf %s \"$0\""],
            None,
            "/h",
        );
        assert!(c.get_envs().next().is_none());
        let (_, out, _) = run_timeout(c, Duration::from_secs(10)).unwrap();
        assert_eq!(out, b"renamed");
        // with a user, HOME is set (nothing is spawned: dropping needs root)
        let me = AsUser { uid: 1, gid: 2 };
        let c = command("sh", None, &["a", "b"], Some(me), "/home/x");
        let envs: Vec<_> = c.get_envs().collect();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "HOME");
        assert_eq!(envs[0].1, Some(std::ffi::OsStr::new("/home/x")));
        assert_eq!(c.get_args().count(), 2);
    }

    #[test]
    fn signal_via_falls_back_to_the_owner_only_on_eperm() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        let owner = |p: u32, s: i32| {
            calls.borrow_mut().push((p, s));
            true
        };
        assert!(signal_via(|_, _| Ok(()), 7, 15, &owner));
        assert!(calls.borrow().is_empty());
        assert!(signal_via(|_, _| Err(libc::EPERM), 7, 15, &owner));
        assert_eq!(*calls.borrow(), [(7, 15)]);
        // another errno: not delivered, owner not asked
        assert!(!signal_via(|_, _| Err(libc::ESRCH), 8, 9, &owner));
        assert_eq!(calls.borrow().len(), 1);
        // owner refuses too
        assert!(!signal_via(|_, _| Err(libc::EPERM), 7, 15, &|_, _| false));
        // the kill closure gets pid and signal in that order
        let seen = RefCell::new(None);
        signal_via(
            |p, s| {
                *seen.borrow_mut() = Some((p, s));
                Ok(())
            },
            41,
            2,
            &owner,
        );
        assert_eq!(*seen.borrow(), Some((41, 2)));
    }

    #[test]
    fn signal_reaches_a_real_child_and_reports_a_missing_pid() {
        use std::os::unix::process::ExitStatusExt;
        let mut c = Command::new("sleep").arg("100").spawn().unwrap();
        assert!(signal(c.id(), libc::SIGTERM, &|_, _| false));
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
        // reaped: ESRCH, which is not EPERM, so the owner must not be consulted
        assert!(!signal(c.id(), libc::SIGTERM, &|_, _| panic!(
            "asked the owner"
        )));
    }

    fn sh_child(script: &str) -> Option<Child> {
        Some(Command::new("sh").args(["-c", script]).spawn().unwrap())
    }

    fn gone(pid: u32) -> bool {
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    #[test]
    fn kill_proc_uses_sigterm_for_others_and_reaps() {
        // ignores INT, dies on TERM
        let mut child = sh_child("trap '' INT; trap 'exit 0' TERM; while :; do sleep 0.05; done");
        let pid = child.as_ref().unwrap().id();
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        kill_proc(&mut child, "Vanguards", Duration::from_secs(5), &|_, _| {
            false
        });
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
        assert!(gone(pid), "left a zombie");
    }

    #[test]
    fn kill_proc_uses_sigint_for_tor() {
        // ignores TERM, dies on INT
        let mut child = sh_child("trap '' TERM; trap 'exit 0' INT; while :; do sleep 0.05; done");
        let pid = child.as_ref().unwrap().id();
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        kill_proc(&mut child, "Tor", Duration::from_secs(5), &|_, _| false);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
        assert!(gone(pid), "left a zombie");
    }

    #[test]
    fn kill_proc_escalates_to_sigkill_after_the_timeout() {
        let mut child = sh_child("trap '' INT TERM; while :; do sleep 0.05; done");
        let pid = child.as_ref().unwrap().id();
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        kill_proc(&mut child, "Tor", Duration::from_millis(400), &|_, _| false);
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(400), "{took:?}");
        assert!(took < Duration::from_secs(4), "{took:?}");
        assert!(gone(pid), "left a zombie");
    }

    #[test]
    fn kill_proc_leaves_an_already_exited_or_absent_child_alone() {
        let mut none: Option<Child> = None;
        kill_proc(&mut none, "x", Duration::from_secs(1), &|_, _| {
            panic!("signalled")
        });
        let mut done = sh_child("exit 0");
        done.as_mut().unwrap().wait().unwrap();
        kill_proc(&mut done, "x", Duration::from_secs(1), &|_, _| {
            panic!("signalled")
        });
    }

    #[test]
    fn drop_verdict_is_false_only_for_uid_zero() {
        assert_eq!(drop_verdict("Name:\tx\nUid:\t0\t0\t0\t0\n"), Some(false));
        assert_eq!(drop_verdict("Uid:\t100\t100\t100\t100\n"), Some(true));
        assert_eq!(drop_verdict("Uid:\t1\t0\t0\t0\n"), Some(true));
        assert_eq!(drop_verdict("Name:\tx\n"), None);
        assert_eq!(drop_verdict("Uid:\tgarbage\n"), None);
    }

    #[test]
    fn assert_process_dropped_accepts_a_child_running_as_a_normal_user() {
        if is_root() {
            return;
        }
        let mut c = Command::new("sleep").arg("100").spawn().unwrap();
        let mut log = Vec::new();
        assert!(assert_process_dropped(&c, "Tor", &mut log));
        assert!(log.is_empty(), "{log:?}");
        c.kill().unwrap();
        c.wait().unwrap();
    }

    #[test]
    fn assert_process_dropped_gives_up_after_five_seconds_on_a_vanished_pid() {
        let mut c = Command::new("true").spawn().unwrap();
        c.wait().unwrap(); // reaped: /proc/<pid> is gone
        let mut log = Vec::new();
        let started = Instant::now();
        assert!(!assert_process_dropped(&c, "Tor", &mut log));
        let took = started.elapsed();
        assert!(
            took >= Duration::from_secs(5) && took < Duration::from_secs(8),
            "{took:?}"
        );
        assert_eq!(
            log,
            ["FATAL: could not confirm Tor dropped privileges within 5s."]
        );
    }

    #[test]
    fn uid_from_status_reads_the_real_uid_only() {
        assert_eq!(uid_from_status("Uid:\t5\t6\t7\t8\n"), Some(5));
        assert_eq!(uid_from_status("Gid:\t5\nUid:\t9\t9\t9\t9\n"), Some(9));
        assert_eq!(uid_from_status("Uid:\t\n"), None);
    }

    #[test]
    fn self_exe_is_the_running_binary() {
        let me = std::env::current_exe().unwrap();
        assert_eq!(self_exe(), me.to_string_lossy());
        assert!(std::path::Path::new(&self_exe()).is_absolute());
        // the fallback path is only for a /proc that cannot be read
        assert_ne!(self_exe(), "/usr/local/bin/hiddenforge");
    }

    #[test]
    fn is_root_matches_the_effective_uid_in_proc() {
        let st = std::fs::read_to_string("/proc/self/status").unwrap();
        let euid: u32 = status_field(&st, "Uid:")
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(is_root(), euid == 0);
    }
}
