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
    hay.windows(needle.len()).any(|w| w == needle)
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

fn hidden_service_dirs(torrc: &str) -> Option<Vec<String>> {
    let bytes = std::fs::read(torrc).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let mut out: Vec<String> = Vec::new();
    // Python iterates file lines (split on \n only), and `$` allows the trailing \n.
    for line in text.split_inclusive('\n') {
        let l = line.strip_suffix('\n').unwrap_or(line);
        let t = l.trim_start_matches(char::is_whitespace);
        let Some(rest) = t.strip_prefix("HiddenServiceDir") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start_matches(char::is_whitespace);
        let val: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        if val.is_empty() || !rest[val.len()..].chars().all(char::is_whitespace) {
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
    if json {
        let mut out = Json::obj()
            .with("ok", (rc == 0).into())
            .with("exit_code", Json::Int(i64::from(rc)));
        if let Json::Obj(items) = doc {
            for (k, v) in items {
                out.set(&k, v);
            }
        }
        println!("{}", py::dumps(&out, true, None));
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
        println!("healthcheck: ready{suffix}");
    } else {
        let reason = match doc.get("reason") {
            Some(Json::Str(r)) => r.clone(),
            _ => "None".into(),
        };
        println!("healthcheck: not ready - {reason}");
    }
    rc
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
            let text = String::from_utf8_lossy(&line);
            let f: Vec<&str> = text.split_whitespace().collect();
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
