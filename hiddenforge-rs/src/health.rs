//! The healthcheck (port of healthcheck.py) and the descriptor-upload watcher.
//!
//! Same states, same reasons, same JSON (sorted keys), same exit codes:
//! 0 ready, 1 not ready, 2 cannot evaluate.

use crate::fsops;
use crate::py::{self, Json};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub const CONTROL_SOCKET: &str = "/var/lib/tor/control.sock";
pub const TORRC: &str = "/etc/tor/torrc";
pub const UPLOADS_FILE: &str = "/var/lib/tor/hs-uploaded";
const UPLOADS_MAX_BYTES: usize = 65536;
/// argv[0] of the guards process (the bandguards/rendguard port).
pub const GUARDS_ARGV0: &str = "hiddenforge-guards";

pub struct Env {
    pub proc_root: String,
    pub control_socket: String,
    pub torrc: String,
    pub uploads: String,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            proc_root: "/proc".into(),
            control_socket: CONTROL_SOCKET.into(),
            torrc: TORRC.into(),
            uploads: UPLOADS_FILE.into(),
        }
    }
}

fn each_cmdline(proc_root: &str) -> Vec<Vec<u8>> {
    let Ok(rd) = std::fs::read_dir(proc_root) else {
        return vec![];
    };
    rd.flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .collect()
}

fn argv0_basename(cmdline: &[u8]) -> String {
    let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or(&[]);
    let s = String::from_utf8_lossy(argv0);
    s.rsplit('/').next().unwrap_or("").to_string()
}

pub fn tor_running(proc_root: &str) -> bool {
    each_cmdline(proc_root)
        .iter()
        .any(|c| !c.is_empty() && argv0_basename(c) == "tor")
}

pub fn guards_running(proc_root: &str) -> bool {
    each_cmdline(proc_root)
        .iter()
        .any(|c| argv0_basename(c) == GUARDS_ARGV0)
}

/// `str(OSError)` for a failed socket connect/recv, as healthcheck.py reported it.
fn sock_err(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n)
            if e.kind() != std::io::ErrorKind::TimedOut
                && e.kind() != std::io::ErrorKind::WouldBlock =>
        {
            py::oserror(n)
        }
        _ => "timed out".to_string(),
    }
}

fn query(sock: &str) -> Result<Vec<u8>, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| sock_err(&e))?;
    let t = Some(Duration::from_secs(5));
    s.set_read_timeout(t).map_err(|e| sock_err(&e))?;
    s.set_write_timeout(t).map_err(|e| sock_err(&e))?;
    s.write_all(
        b"AUTHENTICATE\r\nGETINFO status/circuit-established\r\nGETINFO status/bootstrap-phase\r\nGETINFO circuit-status\r\nQUIT\r\n",
    )
    .map_err(|e| sock_err(&e))?;
    let mut data = Vec::new();
    let mut buf = vec![0u8; 65536];
    while !contains(&data, b"250 closing connection") {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(sock_err(&e)),
        }
    }
    Ok(data)
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    // Python: b"" in anything is True (and windows(0) would panic).
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// CPython str.splitlines().
pub fn splitlines(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(std::mem::take(&mut cur));
            }
            '\n' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}'
            | '\u{2029}' => {
                out.push(std::mem::take(&mut cur));
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Python's `str.isspace()` (and regex `\s`) for one character.
fn is_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\x1c'..='\x1f')
}

fn hidden_service_dirs(torrc: &str) -> Option<Vec<String>> {
    let bytes = std::fs::read(torrc).ok()?;
    // open() in text mode uses universal newlines: \r\n and a lone \r break a line.
    let text = String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut out: Vec<String> = Vec::new();
    for line in text.split_inclusive('\n') {
        let l = line.strip_suffix('\n').unwrap_or(line);
        let t = l.trim_start_matches(is_space);
        let Some(rest) = t.strip_prefix("HiddenServiceDir") else {
            continue;
        };
        if !rest.starts_with(is_space) {
            continue;
        }
        let rest = rest.trim_start_matches(is_space);
        let val: String = rest.chars().take_while(|c| !is_space(*c)).collect();
        if val.is_empty() || !rest[val.len()..].chars().all(is_space) {
            continue;
        }
        if !out.contains(&val) {
            out.push(val);
        }
    }
    Some(out)
}

fn read_address_file(path: &str, max: usize) -> Option<String> {
    let data = fsops::read_small_regular_file(path, max).ok()?;
    if !data.is_ascii() {
        return None;
    }
    Some(py::strip_str(std::str::from_utf8(&data).ok()?).to_string())
}

pub fn uploaded_addresses(path: &str) -> Vec<String> {
    match read_address_file(path, UPLOADS_MAX_BYTES) {
        Some(t) if !t.is_empty() => {
            let mut v: Vec<String> = t
                .split('\n')
                .filter(|l| fsops::is_label(l))
                .map(String::from)
                .collect();
            v.sort();
            v.dedup();
            v
        }
        _ => vec![],
    }
}

fn circuit_status_lines(resp: &[u8]) -> Vec<String> {
    let lines = splitlines(&String::from_utf8_lossy(resp));
    let Some(start) = lines.iter().position(|l| l == "250+circuit-status=") else {
        return vec![];
    };
    let mut body = Vec::new();
    for line in &lines[start + 1..] {
        if line == "." {
            return body;
        }
        body.push(
            line.strip_prefix('.')
                .filter(|_| line.starts_with(".."))
                .unwrap_or(line)
                .to_string(),
        );
    }
    vec![]
}

fn is_word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

fn rend_query(line: &str) -> Option<String> {
    let key = "REND_QUERY=";
    let mut from = 0;
    while let Some(i) = line[from..].find(key) {
        let at = from + i;
        let before = line[..at].chars().last();
        let val_start = at + key.len();
        let val: String = line[val_start..].chars().take(56).collect();
        let after = line[val_start..].chars().nth(56);
        if !is_word(before) && val.chars().count() == 56 && fsops::is_label(&val) && !is_word(after)
        {
            return Some(val);
        }
        from = at + 1;
    }
    None
}

fn intro_points(resp: &[u8]) -> Vec<(String, i64)> {
    let mut counts: Vec<(String, i64)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for raw in circuit_status_lines(resp) {
        let line = py::strip_str(&raw);
        if !line.contains("PURPOSE=HS_SERVICE_INTRO") || !line.contains("HS_STATE=HSSI_ESTABLISHED")
        {
            continue;
        }
        let Some(addr) = rend_query(line) else {
            continue;
        };
        let id = line.split(' ').next().unwrap_or("").to_string();
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        match counts.iter_mut().find(|(a, _)| *a == addr) {
            Some(slot) => slot.1 += 1,
            None => counts.push((addr, 1)),
        }
    }
    counts
}

pub fn evaluate(env: &Env) -> (i32, Json) {
    let mut doc = Json::obj()
        .with("process_up", tor_running(&env.proc_root).into())
        .with("tor_bootstrapped", false.into())
        .with("circuit_established", false.into())
        .with("hidden_service_published", false.into())
        .with("hidden_service_reachable", false.into())
        .with("vanguards", false.into())
        .with("ready", false.into())
        .with("services", Json::Arr(vec![]))
        .with("reason", Json::Null);
    let resp = match query(&env.control_socket) {
        Ok(r) => r,
        Err(e) => {
            doc.set("reason", format!("cannot reach control socket: {e}").into());
            return (2, doc);
        }
    };
    if !contains(&resp, b"250 closing connection") {
        doc.set(
            "reason",
            "control socket reply was truncated - cannot evaluate (this is not a statement that the service is down)"
                .into(),
        );
        return (2, doc);
    }
    let boot = contains(&resp, b"PROGRESS=100");
    let circ = contains(&resp, b"circuit-established=1");
    let guards = guards_running(&env.proc_root);
    doc.set("circuit_established", circ.into());
    doc.set("tor_bootstrapped", boot.into());
    doc.set("vanguards", guards.into());

    let Some(dirs) = hidden_service_dirs(&env.torrc) else {
        doc.set(
            "reason",
            format!(
                "cannot read {} - cannot tell which services to check",
                env.torrc
            )
            .into(),
        );
        return (2, doc);
    };
    let mut details = Vec::new();
    let mut published = !dirs.is_empty();
    for d in &dirs {
        let name = d
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        let onion = read_address_file(&format!("{d}/hostname"), 256);
        let ok = onion.as_deref().is_some_and(fsops::is_onion);
        published = published && ok;
        details.push((name, if ok { onion } else { None }, ok));
    }
    doc.set("hidden_service_published", published.into());

    let intro = intro_points(&resp);
    let uploaded = uploaded_addresses(&env.uploads);
    let (mut unreachable, mut not_uploaded) = (Vec::new(), Vec::new());
    let mut services = Vec::new();
    for (name, addr, ok) in &details {
        let label = addr
            .as_deref()
            .map(|a| a.trim_end_matches(".onion").to_string());
        let ip = label
            .as_ref()
            .and_then(|l| intro.iter().find(|(a, _)| a == l))
            .map_or(0, |(_, n)| *n);
        let up = label.as_ref().is_some_and(|l| uploaded.contains(l));
        if *ok && ip < 1 {
            unreachable.push(name.clone());
        } else if *ok && !up {
            not_uploaded.push(name.clone());
        }
        services.push(
            Json::obj()
                .with("name", name.as_str().into())
                .with("address", addr.clone().into())
                .with("published", (*ok).into())
                .with("intro_points", Json::Int(ip))
                .with("descriptor_uploaded", up.into()),
        );
    }
    let reachable = !details.is_empty() && unreachable.is_empty() && not_uploaded.is_empty();
    doc.set("services", Json::Arr(services));
    doc.set("hidden_service_reachable", reachable.into());

    let reason: Option<String> = if dirs.is_empty() {
        Some("no onion service is configured - every mapping was dropped at startup; `hiddenforge status` lists why".into())
    } else if !boot {
        Some("bootstrap not at 100%".into())
    } else if !circ {
        Some("no circuit established yet".into())
    } else if !published {
        let missing: Vec<&str> = details
            .iter()
            .filter(|d| !d.2)
            .map(|d| d.0.as_str())
            .collect();
        Some(format!(
            "hidden service(s) not published yet: {}",
            missing.join(", ")
        ))
    } else if !reachable && unreachable.is_empty() {
        Some(format!(
            "no descriptor uploaded to the network yet for: {} - clients cannot find it. Tor uploads within about a minute of its introduction points.",
            not_uploaded.join(", ")
        ))
    } else if !reachable {
        Some(format!(
            "hostname exists but Tor has no established introduction points for: {} - NOT reachable by any client, whatever the hostname file says. Check the Tor log for guard or circuit failures.",
            unreachable.join(", ")
        ))
    } else if !guards {
        Some("Tor is serving but the Vanguards addon is NOT running - bandguards and rendguard are gone. It is retried automatically; restarting the container retries at once.".into())
    } else {
        None
    };
    match reason {
        Some(r) => {
            doc.set("reason", r.into());
            (1, doc)
        }
        None => {
            doc.set("ready", true.into());
            (0, doc)
        }
    }
}

/// `healthcheck.py [--json]`.
pub fn main_check(json: bool) -> i32 {
    let (rc, doc) = evaluate(&Env::default());
    println!("{}", render(rc, doc, json));
    rc
}

/// The one line (or JSON document) `healthcheck.py` prints for a verdict.
fn render(rc: i32, doc: Json, json: bool) -> String {
    if json {
        let mut out = Json::obj()
            .with("ok", (rc == 0).into())
            .with("exit_code", Json::Int(i64::from(rc)));
        if let Json::Obj(items) = doc {
            for (k, v) in items {
                out.set(&k, v);
            }
        }
        py::dumps(&out, true, None)
    } else if rc == 0 {
        let addrs: Vec<String> = match doc.get("services") {
            Some(Json::Arr(s)) => s
                .iter()
                .filter_map(|x| match x.get("address") {
                    Some(Json::Str(a)) if !a.is_empty() => Some(a.clone()),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        let suffix = if addrs.is_empty() {
            String::new()
        } else {
            format!(" - {}", addrs.join(", "))
        };
        format!("healthcheck: ready{suffix}")
    } else {
        let reason = match doc.get("reason") {
            Some(Json::Str(r)) => r.clone(),
            _ => "None".into(),
        };
        format!("healthcheck: not ready - {reason}")
    }
}

fn write_uploaded(path: &str, addresses: &[String]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.{}.tmp", std::process::id());
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT|O_EXCL: never an existing inode
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&tmp)?;
    let body: String = addresses.iter().map(|a| format!("{a}\n")).collect();
    f.write_all(body.as_bytes())?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// `healthcheck.py --watch-uploads`: record each HS_DESC UPLOADED address until Tor goes.
pub fn watch_uploads(path: &str, sock_path: &str, connect_timeout: Duration) -> i32 {
    let mut uploaded = uploaded_addresses(path);
    let deadline = Instant::now() + connect_timeout;
    let mut s = loop {
        match UnixStream::connect(sock_path) {
            Ok(s) => break s,
            Err(_) => {
                if Instant::now() > deadline {
                    return 2;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    };
    if s.write_all(b"AUTHENTICATE\r\nSETEVENTS HS_DESC\r\n")
        .is_err()
    {
        return 1;
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 65536];
    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) => return 0,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return 1,
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 1 << 20 && !contains(&buf, b"\r\n") {
            buf.clear();
        }
        while let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = buf.drain(..i + 2).take(i).collect();
            // line.decode("ascii", "replace").split()
            let text: String = line
                .iter()
                .map(|&b| if b < 0x80 { char::from(b) } else { '\u{fffd}' })
                .collect();
            let f: Vec<&str> = text.split(is_space).filter(|x| !x.is_empty()).collect();
            if f.len() >= 4
                && f[..3] == ["650", "HS_DESC", "UPLOADED"]
                && fsops::is_label(f[3])
                && !uploaded.iter().any(|a| a == f[3])
            {
                uploaded.push(f[3].to_string());
                uploaded.sort();
                // A failed record leaves readiness withheld (safe direction).
                let _ = write_uploaded(path, &uploaded);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};

    const ONION: &str = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd";
    const REQUEST: &[u8] = b"AUTHENTICATE\r\nGETINFO status/circuit-established\r\nGETINFO status/bootstrap-phase\r\nGETINFO circuit-status\r\nQUIT\r\n";

    // ---------------------------------------------------------------- helpers

    /// A scratch directory that is removed even when the test panics.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            static N: AtomicU32 = AtomicU32::new(0);
            let d = std::env::temp_dir().join(format!(
                "hf-health-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn p(&self, rel: &str) -> String {
            self.0.join(rel).to_string_lossy().into_owned()
        }
        fn put(&self, rel: &str, data: &[u8]) -> String {
            let p = self.0.join(rel);
            if let Some(dir) = p.parent() {
                std::fs::create_dir_all(dir).unwrap();
            }
            std::fs::write(&p, data).unwrap();
            p.to_string_lossy().into_owned()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn accept_then<T>(l: UnixListener, script: impl FnOnce(UnixStream) -> T) -> T {
        l.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            match l.accept() {
                Ok((c, _)) => {
                    c.set_nonblocking(false).unwrap();
                    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    return script(c);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("fake control server: {e}"),
            }
        }
    }

    /// Bind now, accept ONE connection on a thread and hand it to `script`.
    fn serve<T: Send + 'static>(
        sock: &str,
        script: impl FnOnce(UnixStream) -> T + Send + 'static,
    ) -> JoinHandle<T> {
        let l = UnixListener::bind(sock).unwrap();
        thread::spawn(move || accept_then(l, script))
    }

    fn read_until(c: &mut UnixStream, needle: &[u8]) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !contains(&got, needle) {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        got
    }

    fn pause() {
        thread::sleep(Duration::from_millis(60));
    }

    fn label(c: char) -> String {
        c.to_string().repeat(56)
    }

    fn intro_with(cid: &str, addr: &str, state: &str, purpose: &str) -> String {
        format!(
            "{cid} BUILT $AAAA~guard,$BBBB~middle,$CCCC~intro PURPOSE={purpose} HS_STATE={state} REND_QUERY={addr} TIME_CREATED=2026-09-18T00:00:00.000000"
        )
    }

    fn intro(cid: &str, addr: &str) -> String {
        intro_with(cid, addr, "HSSI_ESTABLISHED", "HS_SERVICE_INTRO")
    }

    /// Tor's reply to the four queries, as the Python tests build it.
    fn circuit_reply(lines: &[String]) -> Vec<u8> {
        let body: String = lines.iter().map(|l| format!("{l}\r\n")).collect();
        format!(
            "250 OK\r\n250-status/circuit-established=1\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250+circuit-status=\r\n{body}.\r\n250 OK\r\n250 closing connection\r\n"
        )
        .into_bytes()
    }

    // ----------------------------------------------------------- sock_err

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn sock_err_prints_what_str_of_the_oserror_printed() {
        let os = |n: i32| sock_err(&std::io::Error::from_raw_os_error(n));
        assert_eq!(os(libc::ENOENT), "[Errno 2] No such file or directory");
        assert_eq!(os(libc::EACCES), "[Errno 13] Permission denied");
        assert_eq!(os(libc::ECONNRESET), "[Errno 104] Connection reset by peer");
        assert_eq!(os(libc::ECONNREFUSED), "[Errno 111] Connection refused");
        // socket.settimeout() expiry is EAGAIN here and TimeoutError('timed out') there.
        assert_eq!(os(libc::EAGAIN), "timed out");
        // Open decision (not changed): ETIMEDOUT also reads "timed out"; healthcheck.py
        // printed "[Errno 110] Connection timed out".
        assert_eq!(os(libc::ETIMEDOUT), "timed out");
        let no_errno = std::io::Error::other("x");
        assert_eq!(sock_err(&no_errno), "timed out");
    }

    // ---------------------------------------------------- /proc scanning

    /// (processes as (pid, cmdline), tor_running, guards_running)
    type Row<'a> = (&'a [(&'a str, &'a [u8])], bool, bool);

    fn proc_tree(procs: &[(&str, &[u8])]) -> Tmp {
        let t = Tmp::new("proc");
        for (pid, cmd) in procs {
            t.put(&format!("{pid}/cmdline"), cmd);
        }
        t
    }

    #[test]
    fn each_cmdline_reads_numeric_directories_only() {
        let t = proc_tree(&[
            ("1", b"tor\0-f\0/etc/tor/torrc\0"),
            ("42", b""),
            ("self", b"tor\0"),
            ("sys", b"tor\0"),
        ]);
        std::fs::create_dir(t.p("77")).unwrap(); // exited mid-scan: no cmdline
        t.put("88", b"tor\0"); // a plain file named like a pid
        let mut got = each_cmdline(&t.p(""));
        got.sort();
        assert_eq!(
            got,
            vec![b"".to_vec(), b"tor\0-f\0/etc/tor/torrc\0".to_vec()]
        );
    }

    #[test]
    fn an_unreadable_proc_root_is_no_processes() {
        assert!(each_cmdline("/nonexistent-proc-root").is_empty());
        assert!(!tor_running("/nonexistent-proc-root"));
        assert!(!guards_running("/nonexistent-proc-root"));
    }

    #[test]
    fn tor_and_guards_are_told_apart_by_argv0_alone() {
        let guards_cmd: &[u8] = b"/usr/local/bin/hiddenforge-guards\0--x\0";
        let rows: [Row; 13] = [
            (&[], false, false),
            (&[("1", b"tor\0-f\0/etc/tor/torrc\0")], true, false),
            (&[("1", b"/usr/bin/tor\0")], true, false),
            (&[("1", b"python3\0/entrypoint.py\0")], false, false),
            (
                &[("1", b"tor-gencert\0--create-identity-key\0")],
                false,
                false,
            ),
            (
                // the control socket path contains "tor", argv0 does not
                &[(
                    "1",
                    b"python3\0v\0--control_socket\0/var/lib/tor/control.sock\0",
                )],
                false,
                false,
            ),
            (&[("1", b"hiddenforge-guards\0")], false, true),
            (&[("1", guards_cmd)], false, true),
            (&[("1", b"tor\0hiddenforge-guards\0")], true, false),
            (&[("1", b"")], false, false),
            (
                &[("1", b"tor\0-f\0x\0"), ("2", b"hiddenforge-guards\0")],
                true,
                true,
            ),
            (
                &[("self", b"tor\0"), ("sys", b"hiddenforge-guards\0")],
                false,
                false,
            ),
            (&[("1", b"\xff\xfetor")], false, false),
        ];
        for (procs, tor, guards) in rows {
            let t = proc_tree(procs);
            assert_eq!(tor_running(&t.p("")), tor, "tor_running {procs:?}");
            assert_eq!(guards_running(&t.p("")), guards, "guards_running {procs:?}");
        }
    }

    #[test]
    fn argv0_basename_is_the_text_before_the_first_nul_after_the_last_slash() {
        for (cmd, want) in [
            (&b"/usr/bin/tor\0-f\0/etc/tor/torrc\0"[..], "tor"),
            (b"tor\0-f\0/etc/tor/torrc\0", "tor"),
            (b"tor", "tor"),
            (b"", ""),
            (b"/a/b/\0x", ""),
            (b"python3\0/entrypoint.py\0tor", "python3"),
            (b"\0tor", ""),
            (b"\xff/tor\0", "tor"),
        ] {
            assert_eq!(argv0_basename(cmd), want, "{cmd:?}");
        }
    }

    // ------------------------------------------------------------- query

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn query_sends_the_five_line_request_and_stops_at_the_quit_reply() {
        let t = Tmp::new("q1");
        let sock = t.p("c.sock");
        let reply = circuit_reply(&[intro("1", ONION)]);
        let (tx, rx) = mpsc::channel::<()>();
        let sent = reply.clone();
        let h = serve(&sock, move |mut c| {
            let req = read_until(&mut c, b"QUIT\r\n");
            c.write_all(&sent).unwrap();
            // Tor closes after QUIT, but the client must not depend on it.
            let _ = rx.recv_timeout(Duration::from_secs(15));
            req
        });
        let t0 = Instant::now();
        let got = query(&sock);
        let took = t0.elapsed();
        tx.send(()).unwrap();
        assert_eq!(h.join().unwrap(), REQUEST);
        assert_eq!(got, Ok(reply));
        assert!(took < Duration::from_secs(4), "returned after {took:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn query_reads_a_fragmented_reply_to_its_end() {
        let t = Tmp::new("q2");
        let sock = t.p("c.sock");
        let lines: Vec<String> = (0..40).map(|i| intro(&i.to_string(), ONION)).collect();
        let reply = circuit_reply(&lines);
        let sent = reply.clone();
        let h = serve(&sock, move |mut c| {
            read_until(&mut c, b"QUIT\r\n");
            for piece in sent.chunks(7) {
                if c.write_all(piece).is_err() {
                    break;
                }
            }
        });
        let got = query(&sock);
        h.join().unwrap();
        assert_eq!(got, Ok(reply));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn query_returns_what_arrived_when_the_peer_closes_early() {
        let t = Tmp::new("q3");
        let sock = t.p("c.sock");
        let h = serve(&sock, |mut c| {
            read_until(&mut c, b"QUIT\r\n");
            c.write_all(b"250 OK\r\n").unwrap();
        });
        assert_eq!(query(&sock), Ok(b"250 OK\r\n".to_vec()));
        h.join().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn query_reports_a_reset_connection_like_python() {
        let t = Tmp::new("q4");
        let sock = t.p("c.sock");
        // Never read the request, then close: the kernel resets the peer.
        let h = serve(&sock, |c| {
            thread::sleep(Duration::from_millis(400));
            drop(c);
        });
        assert_eq!(
            query(&sock),
            Err("[Errno 104] Connection reset by peer".to_string())
        );
        h.join().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn query_keeps_a_partial_reply_when_the_peer_goes_silent() {
        let t = Tmp::new("q5");
        let sock = t.p("c.sock");
        let (tx, rx) = mpsc::channel::<()>();
        let h = serve(&sock, move |mut c| {
            read_until(&mut c, b"QUIT\r\n");
            c.write_all(b"250 OK\r\n").unwrap();
            let _ = rx.recv_timeout(Duration::from_secs(20));
        });
        let t0 = Instant::now();
        let got = query(&sock);
        let took = t0.elapsed();
        tx.send(()).unwrap();
        h.join().unwrap();
        assert_eq!(got, Ok(b"250 OK\r\n".to_vec()));
        assert!(
            took >= Duration::from_secs(4) && took < Duration::from_secs(9),
            "the 5 s read timeout, got {took:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn query_names_a_missing_or_dead_socket() {
        assert_eq!(
            query("/nonexistent-dir/c.sock"),
            Err("[Errno 2] No such file or directory".to_string())
        );
        let t = Tmp::new("q6");
        let sock = t.p("stale.sock");
        drop(UnixListener::bind(&sock).unwrap()); // the file stays, nobody listens
        assert_eq!(
            query(&sock),
            Err("[Errno 111] Connection refused".to_string())
        );
    }

    // --------------------------------------------- hidden_service_dirs

    fn dirs_of(content: &[u8]) -> Option<Vec<String>> {
        let t = Tmp::new("torrc");
        let p = t.put("torrc", content);
        hidden_service_dirs(&p)
    }

    fn strs(v: &[&str]) -> Option<Vec<String>> {
        Some(v.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn service_dirs_come_from_the_torrc_lines() {
        for (content, want) in [
            (
                &b"SocksPort 0\nHiddenServiceDir     /var/lib/tor/hidden_service/app\nHiddenServicePort 80 127.0.0.1:8080\nHiddenServiceDir /var/lib/tor/hidden_service/web\n"[..],
                &["/var/lib/tor/hidden_service/app", "/var/lib/tor/hidden_service/web"][..],
            ),
            (b"HiddenServiceDir /a\nHiddenServiceDir /b\nHiddenServiceDir /a\n", &["/a", "/b"]),
            (b"# HiddenServiceDir /not/a/service\nHiddenServiceDir /real\n", &["/real"]),
            (b"  \tHiddenServiceDir\t /a\n", &["/a"]),
            (b"HiddenServiceDir /a", &["/a"]),
            (b"HiddenServiceDir /a   \n", &["/a"]),
            (b"HiddenServiceDir /a\r\n", &["/a"]),
            (b"HiddenServiceDir /a#c\n", &["/a#c"]),
            (b"HiddenServiceDir /a\n\xff\xfe junk\nHiddenServiceDir /b\n", &["/a", "/b"]),
            (b"", &[]),
            (b"\n\n", &[]),
        ] {
            assert_eq!(dirs_of(content), strs(want), "{:?}", String::from_utf8_lossy(content));
        }
    }

    #[test]
    fn lines_that_are_not_exactly_the_directive_are_ignored() {
        for content in [
            &b"HiddenServiceDirX /a\n"[..],
            b"HiddenServiceDirectory /b\n",
            b"HiddenServiceDirGroupReadable 1\n",
            b"hiddenservicedir /c\n",
            b"X HiddenServiceDir /a\n",
            b"HiddenServiceDir /a extra\n",
            b"HiddenServiceDir\n",
            b"HiddenServiceDir \n",
            b"HiddenServiceDir",
        ] {
            assert_eq!(
                dirs_of(content),
                Some(vec![]),
                "{:?}",
                String::from_utf8_lossy(content)
            );
        }
    }

    #[test]
    fn an_unreadable_torrc_is_unknown_not_no_services() {
        assert_eq!(hidden_service_dirs("/nonexistent-torrc"), None);
        let t = Tmp::new("torrc-dir");
        assert_eq!(
            hidden_service_dirs(&t.p("")),
            None,
            "a directory is not a torrc"
        );
    }

    #[test]
    fn python_whitespace_and_line_breaks_apply_to_the_torrc() {
        // open() in text mode turns a lone CR into a line break, and \s matches
        // \x1c..\x1f (str.isspace), so healthcheck.py reads both of these.
        assert_eq!(
            dirs_of(b"HiddenServiceDir /a\rHiddenServiceDir /b\n"),
            strs(&["/a", "/b"])
        );
        assert_eq!(dirs_of(b"HiddenServiceDir\x1c/a\x1d\n"), strs(&["/a"]));
        assert_eq!(dirs_of(b"\x1fHiddenServiceDir /a\n"), strs(&["/a"]));
    }

    // ------------------------------------- address files and uploads list

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn address_files_are_small_regular_ascii_files() {
        let t = Tmp::new("addr");
        let ok = t.put("ok", b"abc  \n\t");
        t.put("empty", b"");
        t.put("blank", b"  \n");
        t.put("ctl", b"x\x1c\n");
        t.put("bad", b"ab\xff");
        t.put("utf8", "é".as_bytes());
        t.put("max", "a".repeat(256).as_bytes());
        t.put("over", "a".repeat(257).as_bytes());
        std::os::unix::fs::symlink(&ok, t.p("link")).unwrap();
        let fifo = std::ffi::CString::new(t.p("fifo")).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        std::fs::create_dir(t.p("dir")).unwrap();

        let read = |n: &str| read_address_file(&t.p(n), 256);
        assert_eq!(read("ok"), Some("abc".into()));
        assert_eq!(read("empty"), Some(String::new()));
        assert_eq!(read("blank"), Some(String::new()));
        assert_eq!(read("ctl"), Some("x".into()));
        assert_eq!(read("bad"), None);
        assert_eq!(read("utf8"), None);
        assert_eq!(read("max"), Some("a".repeat(256)));
        assert_eq!(read("over"), None);
        assert_eq!(read("link"), None, "never follows a symlink");
        assert_eq!(read("fifo"), None, "never blocks on a FIFO");
        assert_eq!(read("dir"), None);
        assert_eq!(read("missing"), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn uploaded_addresses_are_the_sorted_distinct_valid_labels() {
        let t = Tmp::new("uploaded");
        let (a, b) = (label('a'), label('b'));
        let text = format!(
            "{b}\n{a}\n{b}\n{}\n{}\n{}\n {a}\n\n{}\nnot-an-address\n",
            "a".repeat(55),
            "a".repeat(57),
            "A".repeat(56),
            "1".repeat(56),
        );
        let p = t.put("u", text.as_bytes());
        assert_eq!(uploaded_addresses(&p), vec![a.clone(), b.clone()]);
        assert!(uploaded_addresses(&t.p("missing")).is_empty());
        assert!(uploaded_addresses(&t.put("empty", b"")).is_empty());
        assert!(uploaded_addresses(&t.put("blank", b" \n\n")).is_empty());
        assert!(uploaded_addresses(&t.put("junk", b"hello\n")).is_empty());
        assert!(uploaded_addresses(&t.put("nonascii", "é\n".as_bytes())).is_empty());
        // UPLOADS_MAX_BYTES is 65536: the limit itself is read, one byte more is not.
        let pad = |total: usize| {
            let mut s = format!("{a}\n").into_bytes();
            s.resize(total, b'\n');
            s
        };
        assert_eq!(
            uploaded_addresses(&t.put("max", &pad(65536))),
            vec![a.clone()]
        );
        assert!(uploaded_addresses(&t.put("over", &pad(65537))).is_empty());
    }

    #[test]
    fn write_uploaded_replaces_the_file_atomically_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("write");
        let path = t.p("hs-uploaded");
        let (a, b) = (label('a'), label('b'));
        write_uploaded(&path, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{a}\n{b}\n")
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        write_uploaded(&path, std::slice::from_ref(&b)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{b}\n"));
        let names: Vec<_> = std::fs::read_dir(&t.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["hs-uploaded"],
            "no temporary file is left behind"
        );
        write_uploaded(&path, &[]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn write_uploaded_clears_a_stale_temp_file_and_never_follows_a_planted_link() {
        let t = Tmp::new("write2");
        let path = t.p("hs-uploaded");
        let tmp = format!("{path}.{}.tmp", std::process::id());
        std::fs::write(&tmp, b"stale").unwrap();
        write_uploaded(&path, &["x".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");
        assert!(!std::path::Path::new(&tmp).exists());

        let victim = t.put("victim", b"keep");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        write_uploaded(&path, &["y".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "y\n");

        assert!(write_uploaded(&t.p("no-such-dir/f"), &[]).is_err());
    }

    // -------------------------------------- circuit-status parsing

    #[test]
    fn circuit_status_lines_are_scoped_to_one_reply() {
        let one = intro("7", ONION);
        let lines = |r: &[u8]| circuit_status_lines(r);
        assert_eq!(lines(&circuit_reply(std::slice::from_ref(&one))), vec![one]);
        assert!(lines(b"250 OK\r\n250 closing connection\r\n").is_empty());
        assert!(lines(b"").is_empty());
        assert_eq!(
            lines(b"250+circuit-status=\r\n..leading dot\r\nnormal\r\n.\r\n"),
            vec![".leading dot", "normal"]
        );
        assert_eq!(
            lines(b"250+circuit-status=\r\n..\r\n.x\r\n.\r\n"),
            vec![".", ".x"],
            "only a leading `..` is unescaped"
        );
        assert_eq!(
            lines(b"250+circuit-status=\r\none\r\n.\r\n250 OK\r\ntwo\r\n"),
            vec!["one"],
            "the terminator ends the body"
        );
        assert_eq!(
            lines(b"250+circuit-status=\r\n.\r\n"),
            Vec::<String>::new(),
            "an empty body"
        );
        // another reply's multiline block ahead of the circuit list is skipped
        assert_eq!(
            lines(b"250+other=\r\nPURPOSE=HS_SERVICE_INTRO\r\n.\r\n250+circuit-status=\r\nreal\r\n.\r\n"),
            vec!["real"]
        );
    }

    #[test]
    fn an_unterminated_body_yields_nothing_not_a_partial_count() {
        let truncated = format!("250+circuit-status=\r\n{}\r\n", intro("7", ONION));
        assert!(circuit_status_lines(truncated.as_bytes()).is_empty());
    }

    #[test]
    fn only_established_intro_circuits_with_a_full_address_count() {
        let a = ONION;
        let b = label('b');
        let counts = |lines: Vec<String>| intro_points(&circuit_reply(&lines));
        assert_eq!(
            counts(vec![intro("1", a), intro("2", a), intro("3", &b)]),
            vec![(a.to_string(), 2), (b.clone(), 1)]
        );
        for state in ["HSSI_CONNECTING", "HSSI_INTRO_SENT"] {
            assert!(counts(vec![intro_with("1", a, state, "HS_SERVICE_INTRO")]).is_empty());
        }
        for purpose in [
            "GENERAL",
            "HS_SERVICE_HSDIR",
            "HS_CLIENT_INTRO",
            "CONFLUX_LINKED",
        ] {
            assert!(counts(vec![intro_with("1", a, "HSSI_ESTABLISHED", purpose)]).is_empty());
        }
        let l = intro("9", a);
        assert_eq!(counts(vec![l.clone(), l]), vec![(a.to_string(), 1)]);
        assert!(counts(vec![
            "5 BUILT $A~g PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED".into()
        ])
        .is_empty());
        assert!(counts(vec![intro("1", &"a".repeat(55))]).is_empty());
        assert!(counts(vec![intro("1", &"a".repeat(57))]).is_empty());
        // the trigger text in another reply invents no circuits
        let other = format!(
            "250-status/bootstrap-phase=NOTICE PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY={a}\r\n250 closing connection\r\n"
        );
        assert!(intro_points(other.as_bytes()).is_empty());
    }

    // ---------------------------------------------------------- evaluate

    /// A container's worth of state: fake /proc, torrc, hostname files, uploads
    /// list and a control socket answering with `reply`.
    struct Sc {
        reply: Option<Vec<u8>>,
        services: Vec<(&'static str, Option<String>)>,
        tor: bool,
        guards: bool,
        uploaded: Option<Vec<String>>,
        torrc: bool,
    }

    impl Sc {
        fn new(reply: Vec<u8>) -> Sc {
            Sc {
                reply: Some(reply),
                services: vec![],
                tor: true,
                guards: true,
                uploaded: None,
                torrc: true,
            }
        }
        fn svc(mut self, name: &'static str, hostname: Option<&str>) -> Sc {
            self.services.push((name, hostname.map(String::from)));
            self
        }
        fn onion(self, name: &'static str, label: &str) -> Sc {
            self.svc(name, Some(&format!("{label}.onion\n")))
        }
        fn run(self) -> (i32, Json) {
            let t = Tmp::new("eval");
            let env = Env {
                proc_root: t.p("proc"),
                control_socket: t.p("c.sock"),
                torrc: t.p("torrc"),
                uploads: t.p("hs-uploaded"),
            };
            std::fs::create_dir_all(&env.proc_root).unwrap();
            t.put("proc/1/cmdline", b"hiddenforge\0supervise\0");
            if self.tor {
                t.put("proc/7/cmdline", b"tor\0-f\0/etc/tor/torrc\0");
            }
            if self.guards {
                t.put(
                    "proc/9/cmdline",
                    b"hiddenforge-guards\0--control_socket\0/var/lib/tor/control.sock\0",
                );
            }
            let mut torrc = String::from("SocksPort 0\n");
            let mut labels = Vec::new();
            for (name, hostname) in &self.services {
                let dir = t.p(&format!("hs/{name}"));
                std::fs::create_dir_all(&dir).unwrap();
                torrc += &format!("HiddenServiceDir {dir}\nHiddenServicePort 80 127.0.0.1:80\n");
                if let Some(h) = hostname {
                    t.put(&format!("hs/{name}/hostname"), h.as_bytes());
                    labels.push(h.trim().trim_end_matches(".onion").to_string());
                }
            }
            if self.torrc {
                t.put("torrc", torrc.as_bytes());
            }
            let uploaded = self.uploaded.unwrap_or(labels);
            if !uploaded.is_empty() {
                let body: String = uploaded.iter().map(|l| format!("{l}\n")).collect();
                t.put("hs-uploaded", body.as_bytes());
            }
            let server = self.reply.map(|reply| {
                serve(&env.control_socket, move |mut c| {
                    read_until(&mut c, b"QUIT\r\n");
                    for piece in reply.chunks(100) {
                        if c.write_all(piece).is_err() {
                            break;
                        }
                    }
                })
            });
            let out = evaluate(&env);
            if let Some(h) = server {
                h.join().unwrap();
            }
            out
        }
    }

    fn flag(doc: &Json, k: &str) -> bool {
        match doc.get(k) {
            Some(Json::Bool(b)) => *b,
            other => panic!("{k}: {other:?}"),
        }
    }

    fn reason(doc: &Json) -> String {
        match doc.get("reason") {
            Some(Json::Str(s)) => s.clone(),
            other => panic!("reason: {other:?}"),
        }
    }

    fn service(doc: &Json, i: usize) -> &Json {
        match doc.get("services") {
            Some(Json::Arr(v)) => &v[i],
            other => panic!("services: {other:?}"),
        }
    }

    fn intro_of(doc: &Json, i: usize) -> Json {
        service(doc, i).get("intro_points").cloned().unwrap()
    }

    fn three(addr: &str) -> Vec<String> {
        (0..3).map(|i| intro(&i.to_string(), addr)).collect()
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_healthy_container_is_ready() {
        let (rc, doc) = Sc::new(circuit_reply(&three(ONION)))
            .onion("app", ONION)
            .run();
        assert_eq!(rc, 0);
        assert_eq!(
            py::dumps(&doc, true, None),
            format!(
                r#"{{"circuit_established": true, "hidden_service_published": true, "hidden_service_reachable": true, "process_up": true, "ready": true, "reason": null, "services": [{{"address": "{ONION}.onion", "descriptor_uploaded": true, "intro_points": 3, "name": "app", "published": true}}], "tor_bootstrapped": true, "vanguards": true}}"#
            )
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_truncated_reply_cannot_be_evaluated() {
        let mut reply = circuit_reply(&three(ONION));
        reply.truncate(reply.len() - "250 closing connection\r\n".len());
        let (rc, doc) = Sc::new(reply).onion("app", ONION).run();
        assert_eq!(rc, 2);
        assert_eq!(
            reason(&doc),
            "control socket reply was truncated - cannot evaluate (this is not a statement that the service is down)"
        );
        assert!(!flag(&doc, "ready"));
        assert!(
            !flag(&doc, "circuit_established"),
            "nothing is trusted from a short read"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_missing_control_socket_cannot_be_evaluated() {
        let mut sc = Sc::new(vec![]).onion("app", ONION);
        sc.reply = None;
        sc.tor = false;
        let (rc, doc) = sc.run();
        assert_eq!(rc, 2);
        assert_eq!(
            reason(&doc),
            "cannot reach control socket: [Errno 2] No such file or directory"
        );
        assert!(!flag(&doc, "process_up"));
        assert!(!flag(&doc, "ready"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn an_unreadable_torrc_cannot_be_evaluated() {
        let mut sc = Sc::new(circuit_reply(&three(ONION))).onion("app", ONION);
        sc.torrc = false;
        let (rc, doc) = sc.run();
        assert_eq!(rc, 2);
        assert!(reason(&doc).starts_with("cannot read "));
        assert!(reason(&doc).ends_with("/torrc - cannot tell which services to check"));
        assert!(flag(&doc, "circuit_established"));
        assert!(flag(&doc, "tor_bootstrapped"));
        assert!(flag(&doc, "vanguards"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn no_configured_service_is_never_ready() {
        let (rc, doc) = Sc::new(circuit_reply(&three(ONION))).run();
        assert_eq!(rc, 1);
        assert_eq!(
            reason(&doc),
            "no onion service is configured - every mapping was dropped at startup; `hiddenforge status` lists why"
        );
        assert!(!flag(&doc, "ready"));
        assert!(!flag(&doc, "hidden_service_published"));
        assert!(!flag(&doc, "hidden_service_reachable"));
        assert_eq!(doc.get("services"), Some(&Json::Arr(vec![])));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn an_unfinished_bootstrap_is_reported_first_then_a_missing_circuit() {
        let boot = |progress: &str, circ: &str| {
            format!(
                "250-status/circuit-established={circ}\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress} TAG=x\r\n250 closing connection\r\n"
            )
            .into_bytes()
        };
        let (rc, doc) = Sc::new(boot("45", "0")).onion("app", ONION).run();
        assert_eq!((rc, reason(&doc).as_str()), (1, "bootstrap not at 100%"));
        assert!(!flag(&doc, "tor_bootstrapped"));
        let (rc, doc) = Sc::new(boot("99", "1")).onion("app", ONION).run();
        assert_eq!((rc, reason(&doc).as_str()), (1, "bootstrap not at 100%"));
        let (rc, doc) = Sc::new(boot("100", "0")).onion("app", ONION).run();
        assert_eq!(
            (rc, reason(&doc).as_str()),
            (1, "no circuit established yet")
        );
        assert!(flag(&doc, "tor_bootstrapped"));
        assert!(!flag(&doc, "circuit_established"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn an_unpublished_service_names_itself() {
        let (rc, doc) = Sc::new(circuit_reply(&three(ONION)))
            .onion("good", ONION)
            .svc("bad", None)
            .run();
        assert_eq!(rc, 1);
        assert_eq!(reason(&doc), "hidden service(s) not published yet: bad");
        assert!(!flag(&doc, "hidden_service_published"));
        assert_eq!(
            py::dumps(service(&doc, 1), true, None),
            r#"{"address": null, "descriptor_uploaded": false, "intro_points": 0, "name": "bad", "published": false}"#
        );
        // healthcheck.py only blames published services for reachability
        let (_, doc) = Sc::new(circuit_reply(&[])).svc("only", None).run();
        assert!(flag(&doc, "hidden_service_reachable"));
        assert!(!flag(&doc, "hidden_service_published"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_hostname_that_is_not_an_address_is_not_published() {
        for content in [
            "not-an-onion\n".to_string(),
            format!("{}.onion\n", &ONION[..55]),
            format!("evil{ONION}.onion\n"),
            format!("{ONION}.onion.evil.com\n"),
            "\n".to_string(),
        ] {
            let (rc, doc) = Sc::new(circuit_reply(&[])).svc("app", Some(&content)).run();
            assert_eq!(rc, 1, "{content:?}");
            assert_eq!(reason(&doc), "hidden service(s) not published yet: app");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_published_address_with_no_intro_points_is_not_reachable() {
        let (rc, doc) = Sc::new(circuit_reply(&[])).onion("app", ONION).run();
        assert_eq!(rc, 1);
        assert_eq!(
            reason(&doc),
            "hostname exists but Tor has no established introduction points for: app - NOT reachable by any client, whatever the hostname file says. Check the Tor log for guard or circuit failures."
        );
        assert!(flag(&doc, "hidden_service_published"));
        assert!(!flag(&doc, "hidden_service_reachable"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn intro_points_are_attributed_per_service() {
        let b = label('b');
        let mut lines = vec![intro("1", ONION), intro("2", ONION)];
        let (rc, doc) = Sc::new(circuit_reply(&lines))
            .onion("good", ONION)
            .onion("bad", &b)
            .run();
        assert_eq!(rc, 1);
        assert_eq!(intro_of(&doc, 0), Json::Int(2));
        assert_eq!(intro_of(&doc, 1), Json::Int(0));
        let r = reason(&doc);
        assert!(r.contains("introduction points for: bad - NOT"), "{r}");
        assert!(!r.contains("good"));
        // one established circuit is the floor
        lines.push(intro("3", &b));
        let (rc, doc) = Sc::new(circuit_reply(&lines))
            .onion("good", ONION)
            .onion("bad", &b)
            .run();
        assert_eq!(rc, 0, "{:?}", doc.get("reason"));
        assert_eq!(intro_of(&doc, 1), Json::Int(1));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_service_without_an_uploaded_descriptor_is_not_reachable_yet() {
        let b = label('b');
        let reply = circuit_reply(&[intro("1", ONION), intro("2", &b)]);
        let mut sc = Sc::new(reply.clone()).onion("a", ONION).onion("b", &b);
        sc.uploaded = Some(vec![]);
        let (rc, doc) = sc.run();
        assert_eq!(rc, 1);
        assert_eq!(
            reason(&doc),
            "no descriptor uploaded to the network yet for: a, b - clients cannot find it. Tor uploads within about a minute of its introduction points."
        );
        assert!(!flag(&doc, "hidden_service_reachable"));
        assert_eq!(
            service(&doc, 0).get("descriptor_uploaded"),
            Some(&Json::Bool(false))
        );

        let mut sc = Sc::new(reply).onion("a", ONION).onion("b", &b);
        sc.uploaded = Some(vec![ONION.to_string()]);
        let (rc, doc) = sc.run();
        assert_eq!(rc, 1);
        assert!(reason(&doc).contains("uploaded to the network yet for: b - clients"));
        assert_eq!(
            service(&doc, 0).get("descriptor_uploaded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(
            service(&doc, 1).get("descriptor_uploaded"),
            Some(&Json::Bool(false))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn no_intro_points_outranks_a_missing_upload() {
        let b = label('b');
        // a: circuits but no upload; b: no circuits and no upload
        let mut sc = Sc::new(circuit_reply(&[intro("1", ONION)]))
            .onion("a", ONION)
            .onion("b", &b);
        sc.uploaded = Some(vec![]);
        let (rc, doc) = sc.run();
        assert_eq!(rc, 1);
        let r = reason(&doc);
        assert!(
            r.contains("no established introduction points for: b - NOT"),
            "{r}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_serving_container_without_the_guards_is_not_ready() {
        let mut sc = Sc::new(circuit_reply(&three(ONION))).onion("app", ONION);
        sc.guards = false;
        let (rc, doc) = sc.run();
        assert_eq!(rc, 1);
        assert_eq!(
            reason(&doc),
            "Tor is serving but the Vanguards addon is NOT running - bandguards and rendguard are gone. It is retried automatically; restarting the container retries at once."
        );
        assert!(flag(&doc, "hidden_service_reachable"));
        assert!(!flag(&doc, "vanguards"));
        assert!(!flag(&doc, "ready"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn circuits_in_another_multiline_reply_are_not_counted() {
        let mut reply = b"250+other=\r\n".to_vec();
        reply.extend_from_slice(intro("1", ONION).as_bytes());
        reply.extend_from_slice(b"\r\n.\r\n");
        reply.extend_from_slice(&circuit_reply(&[]));
        let (rc, doc) = Sc::new(reply).onion("app", ONION).run();
        assert_eq!(rc, 1);
        assert_eq!(intro_of(&doc, 0), Json::Int(0));
    }

    // ------------------------------------------------------------ render

    fn doc_with(addresses: &[Option<&str>], reason: Json) -> Json {
        let services = addresses
            .iter()
            .map(|a| Json::obj().with("address", a.map(String::from).into()))
            .collect();
        Json::obj()
            .with("services", Json::Arr(services))
            .with("reason", reason)
    }

    #[test]
    fn the_text_line_is_what_healthcheck_py_prints() {
        let ready = doc_with(
            &[Some("a.onion"), None, Some(""), Some("c.onion")],
            Json::Null,
        );
        assert_eq!(
            render(0, ready, false),
            "healthcheck: ready - a.onion, c.onion"
        );
        assert_eq!(
            render(0, doc_with(&[], Json::Null), false),
            "healthcheck: ready"
        );
        assert_eq!(
            render(0, doc_with(&[None, Some("")], Json::Null), false),
            "healthcheck: ready"
        );
        assert_eq!(
            render(1, doc_with(&[Some("a.onion")], "why".into()), false),
            "healthcheck: not ready - why"
        );
        assert_eq!(
            render(2, doc_with(&[], Json::Null), false),
            "healthcheck: not ready - None"
        );
    }

    #[test]
    fn the_json_document_has_sorted_keys_and_the_exit_code() {
        let doc = Json::obj()
            .with("services", Json::Arr(vec![]))
            .with("reason", "why".into())
            .with("ready", false.into());
        assert_eq!(
            render(1, doc, true),
            r#"{"exit_code": 1, "ok": false, "ready": false, "reason": "why", "services": []}"#
        );
        assert_eq!(
            render(0, Json::obj().with("ready", true.into()), true),
            r#"{"exit_code": 0, "ok": true, "ready": true}"#
        );
        assert_eq!(
            render(2, Json::obj(), true),
            r#"{"exit_code": 2, "ok": false}"#
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn main_check_exits_2_when_there_is_no_control_socket() {
        if std::path::Path::new(CONTROL_SOCKET).exists() {
            return; // a real Tor is here; the verdict would depend on it
        }
        assert_eq!(main_check(false), 2);
        assert_eq!(main_check(true), 2);
    }

    // ----------------------------------------------------- watch_uploads

    fn ev(addr: &str) -> String {
        format!("650 HS_DESC UPLOADED {addr} NO_AUTH $ABCD~hsdir 0000\r\n")
    }

    fn send(c: &mut UnixStream, data: &[u8]) {
        let _ = c.write_all(data);
        pause();
    }

    /// Run the watcher against a fake control port. Returns (exit code, final
    /// file text or "<none>", the request the watcher sent).
    fn run_watch(
        seed: &[String],
        script: impl FnOnce(&mut UnixStream) + Send + 'static,
    ) -> (i32, String, Vec<u8>) {
        let t = Tmp::new("watch");
        let (sock, up) = (t.p("c.sock"), t.p("up"));
        if !seed.is_empty() {
            let body: String = seed.iter().map(|s| format!("{s}\n")).collect();
            t.put("up", body.as_bytes());
        }
        let h = serve(&sock, move |mut c| {
            let req = read_until(&mut c, b"SETEVENTS HS_DESC\r\n");
            script(&mut c);
            req
        });
        let rc = watch_uploads(&up, &sock, Duration::from_secs(5));
        let req = h.join().unwrap();
        let text = std::fs::read_to_string(&up).unwrap_or_else(|_| "<none>".into());
        (rc, text, req)
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn the_watcher_subscribes_and_records_only_real_upload_events() {
        let (a, b, c) = (label('a'), label('b'), label('c'));
        let (b2, c2) = (b.clone(), c.clone());
        let (rc, text, req) = run_watch(&[], move |s| {
            send(s, b"250 OK\r\n250 OK\r\n");
            send(
                s,
                format!("650 HS_DESC REQUESTED {a} NO_AUTH\r\n").as_bytes(),
            );
            send(s, format!("650 HS_DESC UPLOAD {a}\r\n").as_bytes());
            send(s, format!("651 HS_DESC UPLOADED {a} x\r\n").as_bytes());
            send(s, format!("650 HS_EVENT UPLOADED {a} x\r\n").as_bytes());
            send(
                s,
                format!("650 HS_DESC FAILED {a} NO_AUTH $H REASON=X\r\n").as_bytes(),
            );
            send(s, b"650 HS_DESC UPLOADED\r\n");
            send(
                s,
                format!("650 HS_DESC UPLOADED {}\r\n", "a".repeat(55)).as_bytes(),
            );
            send(
                s,
                format!("650 HS_DESC UPLOADED {}\r\n", "a".repeat(57)).as_bytes(),
            );
            send(
                s,
                format!("650 HS_DESC UPLOADED {}\r\n", "A".repeat(56)).as_bytes(),
            );
            send(
                s,
                format!("650 HS_DESC UPLOADED {}\r\n", "1".repeat(56)).as_bytes(),
            );
            send(s, ev(&b2).as_bytes());
            send(s, format!("650  HS_DESC\tUPLOADED   {c2}\r\n").as_bytes());
            send(s, format!("650 HS_DESC UPLOADED {b2}\r\n").as_bytes()); // exactly 4 fields, a repeat
            send(s, ev(&b2).as_bytes());
        });
        assert_eq!(rc, 0, "Tor closing the connection is a clean exit");
        assert_eq!(req, b"AUTHENTICATE\r\nSETEVENTS HS_DESC\r\n");
        assert_eq!(text, format!("{b}\n{c}\n"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn events_in_one_chunk_or_split_across_chunks_are_all_seen() {
        let (a, b, c) = (label('a'), label('b'), label('c'));
        let bundle = format!("{}250 OK\r\n{}{}", ev(&a), ev(&b), ev(&c));
        let (rc, text, _) = run_watch(&[], move |s| {
            send(s, bundle.as_bytes());
            // the next event arrives in pieces, cut inside the CRLF as well
            let tail = ev(&label('d'));
            let cut = tail.len() - 1;
            send(s, &tail.as_bytes()[..10]);
            send(s, &tail.as_bytes()[10..cut]);
            send(s, &tail.as_bytes()[cut..]);
        });
        assert_eq!(rc, 0);
        assert_eq!(
            text,
            format!(
                "{}\n{}\n{}\n{}\n",
                label('a'),
                label('b'),
                label('c'),
                label('d')
            )
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_restarted_watcher_keeps_what_the_earlier_one_recorded() {
        let (a, b, c) = (label('a'), label('b'), label('c'));
        let (a2, b2, c2) = (a.clone(), b.clone(), c.clone());
        // the seeded entry is never re-announced: only the file can supply it
        let (rc, text, _) = run_watch(std::slice::from_ref(&c), move |s| {
            send(s, ev(&b2).as_bytes());
            send(s, ev(&a2).as_bytes());
        });
        assert_eq!(rc, 0);
        assert_eq!(text, format!("{a}\n{b}\n{c}\n"), "sorted, old entry kept");
        // a repeat of a seeded entry changes nothing
        let (rc, text, _) = run_watch(std::slice::from_ref(&c), move |s| {
            send(s, ev(&c2).as_bytes());
        });
        assert_eq!(rc, 0);
        assert_eq!(text, format!("{c}\n"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn event_fields_split_like_pythons_ascii_replace_then_split() {
        // line.decode("ascii", "replace").split(): a non-ASCII byte becomes U+FFFD
        // (not a separator), while \x1c..\x1f separate fields.
        let (a, b) = (label('a'), label('b'));
        let (a2, b2) = (a.clone(), b.clone());
        let (rc, text, _) = run_watch(&[], move |s| {
            send(s, format!("650\u{a0}HS_DESC UPLOADED {a2}\r\n").as_bytes());
            send(s, format!("650 HS_DESC UPLOADED\u{a0}{a2}\r\n").as_bytes());
            send(
                s,
                format!("650\x1cHS_DESC\x1dUPLOADED\x1f{b2}\r\n").as_bytes(),
            );
        });
        assert_eq!(rc, 0);
        assert_eq!(text, format!("{b}\n"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_failed_record_does_not_stop_the_watcher() {
        let t = Tmp::new("watch-nodir");
        let sock = t.p("c.sock");
        let a = label('a');
        let h = serve(&sock, move |mut c| {
            read_until(&mut c, b"SETEVENTS HS_DESC\r\n");
            send(&mut c, ev(&a).as_bytes());
        });
        let rc = watch_uploads(&t.p("no-such-dir/up"), &sock, Duration::from_secs(5));
        h.join().unwrap();
        assert_eq!(rc, 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_line_over_a_mebibyte_with_no_crlf_is_dropped_but_not_one_at_the_limit() {
        let (a, b) = (label('a'), label('b'));
        // Exactly 1 MiB of filler is kept, so the event glues onto it and is lost;
        // the next event is read normally.
        let (a2, b2) = (a.clone(), b.clone());
        let (rc, text, _) = run_watch(&[], move |s| {
            send(s, &vec![b'x'; 1 << 20]);
            thread::sleep(Duration::from_millis(300));
            send(s, ev(&a2).as_bytes());
            send(s, ev(&b2).as_bytes());
        });
        assert_eq!(rc, 0);
        assert_eq!(text, format!("{b}\n"));
        // One byte more is discarded as not an event, so the next event is whole.
        let a3 = a.clone();
        let (rc, text, _) = run_watch(&[], move |s| {
            send(s, &vec![b'x'; (1 << 20) + 1]);
            thread::sleep(Duration::from_millis(300));
            send(s, ev(&a3).as_bytes());
        });
        assert_eq!(rc, 0);
        assert_eq!(text, format!("{a}\n"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_socket_that_appears_late_is_connected_to() {
        let t = Tmp::new("watch-late");
        let (sock, up) = (t.p("c.sock"), t.p("up"));
        let a = label('a');
        let s2 = sock.clone();
        let h = thread::spawn(move || {
            thread::sleep(Duration::from_millis(700));
            let l = UnixListener::bind(&s2).unwrap();
            accept_then(l, move |mut c| {
                read_until(&mut c, b"SETEVENTS HS_DESC\r\n");
                send(&mut c, ev(&a).as_bytes());
            });
        });
        let rc = watch_uploads(&up, &sock, Duration::from_secs(10));
        h.join().unwrap();
        assert_eq!(rc, 0);
        assert_eq!(
            std::fs::read_to_string(&up).unwrap(),
            format!("{}\n", label('a'))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_socket_that_never_appears_is_exit_2_after_the_timeout() {
        let t = Tmp::new("watch-never");
        let t0 = Instant::now();
        let rc = watch_uploads(&t.p("up"), &t.p("none.sock"), Duration::from_secs(1));
        let took = t0.elapsed();
        assert_eq!(rc, 2);
        assert!(
            took >= Duration::from_secs(1) && took < Duration::from_secs(5),
            "{took:?}"
        );
        assert!(!std::path::Path::new(&t.p("up")).exists());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_reset_connection_is_exit_1() {
        let t = Tmp::new("watch-rst");
        let (sock, up) = (t.p("c.sock"), t.p("up"));
        let h = serve(&sock, |c| {
            thread::sleep(Duration::from_millis(400));
            drop(c); // the subscription is unread: the client gets a reset
        });
        let rc = watch_uploads(&up, &sock, Duration::from_secs(5));
        h.join().unwrap();
        assert_eq!(rc, 1);
    }

    // ------------------------------------------- the original unit tests

    #[test]
    fn contains_matches_python_in() {
        assert!(contains(b"abc", b""));
        assert!(contains(b"", b""));
        assert!(contains(b"abc", b"bc"));
        assert!(contains(b"abc", b"abc"));
        assert!(contains(b"abc", b"a"));
        assert!(!contains(b"abc", b"abcd"));
        assert!(!contains(b"abc", b"ac"));
        assert!(!contains(b"", b"a"));
    }

    #[test]
    fn intro_counting_is_scoped_and_deduplicated() {
        let a = "a".repeat(56);
        let resp = format!(
            "250-status/circuit-established=1\r\n250+circuit-status=\r\n\
             1 BUILT x PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY={a} TIME\r\n\
             1 BUILT x PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY={a} TIME\r\n\
             2 BUILT x PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_CONNECTING REND_QUERY={a}\r\n\
             3 BUILT x PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY={a}\r\n.\r\n250 OK\r\n\
             250-x PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY={a}\r\n"
        );
        assert_eq!(intro_points(resp.as_bytes()), vec![(a, 2)]);
    }

    #[test]
    fn truncated_reply_counts_nothing() {
        let resp =
            "250+circuit-status=\r\n1 PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED\r\n";
        assert!(circuit_status_lines(resp.as_bytes()).is_empty());
    }

    #[test]
    fn rend_query_needs_word_boundaries() {
        let a = "b".repeat(56);
        assert!(rend_query(&format!("XREND_QUERY={a}")).is_none());
        assert!(rend_query(&format!("REND_QUERY={a}x")).is_none());
        assert_eq!(rend_query(&format!("1 REND_QUERY={a} T")), Some(a));
    }

    #[test]
    fn splitlines_like_python() {
        assert_eq!(
            splitlines("a\r\nb\rc\nd\x0ce"),
            vec!["a", "b", "c", "d", "e"]
        );
    }
}
