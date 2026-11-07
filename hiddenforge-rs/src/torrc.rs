//! torrc generation: a line-for-line port of entrypoint.build_torrc_string.
//!
//! PURE: no filesystem side effects. Everything the 2.x generator printed is
//! returned in `log` (in order) so the caller prints it and tests can compare it.
//!
//! One deliberate difference from 2.x: ports must be written with ASCII digits.
//! CPython's `\d` and `int()` also accept other Unicode decimal digits (so "٨٠"
//! was port 80); 3.0 refuses those as an invalid port. No real configuration
//! uses them, and accepting them only widens what reaches the torrc.

use crate::py::{self, PyChar, PyStr};

pub const KEYS_ROOT: &str = "/var/lib/tor/hidden_service";
const SUFFIX: &str = "_TOR_SERVICE_HOSTS";

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Torrc {
    pub content: String,
    pub hs_dirs: Vec<String>,
    pub dropped: Vec<String>,
    /// Backend name -> IP written into the torrc (dict order: first insertion).
    pub resolved: Vec<(String, String)>,
    /// Backend names that did not resolve (set semantics, insertion order).
    pub unresolved: Vec<String>,
    pub log: Vec<String>,
}

/// What a lookup of one name returned: the IPv4 addresses, or the
/// `str(socket.gaierror)` text.
pub type Resolver<'a> = &'a dyn Fn(&str) -> Result<Vec<String>, String>;

enum MapErr {
    Unresolved(String),
    Invalid(String),
}

const HEADER: &str = r#"# HiddenForge: hardened Tor configuration
# Generated at container startup. Do not edit by hand.

# ── Control socket (required for Vanguards addon) ──────────────────────────
# Unix socket inside DataDirectory, 0600 owned by tor.  Not reachable from
# other containers.  No password needed; file permissions are the boundary.
ControlSocket /var/lib/tor/control.sock

# ── Network ────────────────────────────────────────────────────────────────
SocksPort 0
DataDirectory /var/lib/tor
ClientOnly 1          # never volunteer as a relay or exit node
ExitPolicy reject *:* # belt-and-suspenders: refuse all exit traffic

# ── Logging ────────────────────────────────────────────────────────────────
Log notice stdout
SafeLogging 1         # scrub IPs / .onion addresses from log output
HeartbeatPeriod 0     # suppress periodic heartbeat log spam

# ── Security hardening ─────────────────────────────────────────────────────
Sandbox @SANDBOX@             # Tor's in-process seccomp-bpf filter; covers Tor only, and
                      # stacks on top of the runtime's own profile (do NOT run unconfined)
DisableDebuggerAttachment 1   # block ptrace / debugger attachment
NoExec 1                      # Tor will never launch another executable, ever
AvoidDiskWrites 1             # minimise forensic footprint on disk
FetchUselessDescriptors 0     # do not fetch relay descriptors we won't use (default, explicit)

# ── Guard-discovery protection ─────────────────────────────────────────────
# vanguards-lite (Tor proposal 333) pins a small set of layer-2 guards so an
# adversary cannot enumerate our position by forcing circuit rebuilds.  It is our
# primary in-Tor defence against guard discovery, and the full Vanguards addon's
# layer-2/3 pinning is NOT running alongside it (see --disable_vanguards below).
#
# Why the addon's pinning is off: it applies its guard sets via SETCONF, and with
# the sandbox enabled EVERY SETCONF fails -- not just guard options.  SETCONF trips
# a full config re-validation, which re-reads the hidden-service directory, which
# the sandbox forbids ("Directory ... cannot be read: Operation not permitted").
# The error surfaces as "Failed to configure rendezvous options" only because that
# is the first check to fail; guard options were never the cause.  Confirmed by
# observing MaxCircuitDirtiness, NewCircuitPeriod and SafeLogging fail identically.
#
# Be honest about what this costs.  Proposal 333 states that vanguards-lite adds
# NO third guard layer, pins only 4 layer-2 guards, makes guard discovery EASIER
# than the full addon, and that long-lived high-risk services relying on it alone
# "might provide those services with a false sense of security" -- such services
# "should still use the vanguards addon".  This deployment is exactly that case.
# Static layer-2/3 node pins written straight into this torrc (no SETCONF) have
# been shown to work with the sandbox enabled, but static pins do not rotate, and
# rotation is the addon's actual design, so that is not a drop-in replacement.
#
# Keep prose in this block free of literal "<Directive> <value>" strings: the
# generated torrc is verified by raw substring matching, so a comment that spells
# one out is indistinguishable from a real config line to those checks.
#
# Pinned to 1, NOT left at the "auto" default.  Per the Tor manual, "auto" means
# "do what the vanguards-lite-enabled consensus parameter tells them to do",
# which puts our only guard-discovery defence under the control of the directory
# authorities rather than the operator.  An adversary able to influence the
# consensus could otherwise disable it for every deployment simultaneously,
# silently.  Setting it explicitly makes that impossible.
VanguardsLiteEnabled 1

# ── Hidden services ────────────────────────────────────────────────────────
"#;

fn is_digits_1_5(s: &[PyChar]) -> bool {
    (1..=5).contains(&s.len()) && s.iter().all(|c| matches!(c, PyChar::C('0'..='9')))
}

/// validate_service_name: `[a-z0-9][a-z0-9-]*`, at most 63 characters.
pub fn validate_service_name(name: &[PyChar]) -> Result<String, String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && matches!(name[0], PyChar::C('a'..='z' | '0'..='9'))
        && name.iter().all(|c| matches!(c, PyChar::C('a'..='z' | '0'..='9' | '-')));
    if ok {
        Ok(py::to_string(name).unwrap_or_default())
    } else {
        Err(format!(
            "Invalid service name '{}': only lowercase alphanumeric and hyphens allowed, max 63 chars",
            py::safe(name)
        ))
    }
}

/// validate_port: digits only, 1..=65535, returned without leading zeros.
pub fn validate_port(value: &[PyChar], label: &[PyChar]) -> Result<String, String> {
    let stripped = py::strip(value);
    if !is_digits_1_5(stripped) {
        return Err(format!("Invalid port '{}' in {}", py::safe(value), py::safe(label)));
    }
    let port: u32 = py::to_string(stripped).unwrap_or_default().parse().unwrap_or(0);
    if !(1..=65535).contains(&port) {
        return Err(format!("Port {port} out of range in {}", py::safe(label)));
    }
    Ok(port.to_string())
}

/// validate_hostname: `[a-zA-Z0-9._-]{1,253}` after strip.
pub fn validate_hostname(value: &[PyChar], label: &[PyChar]) -> Result<String, String> {
    let v = py::strip(value);
    let ok = (1..=253).contains(&v.len())
        && v.iter().all(|c| matches!(c, PyChar::C('a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-')));
    if ok {
        Ok(py::to_string(v).unwrap_or_default())
    } else {
        Err(format!("Invalid hostname '{}' in {}", py::safe(v), py::safe(label)))
    }
}

/// ipaddress.IPv4Address(s) strictness: four decimal octets, no leading zeros,
/// each 0..=255, at most 3 digits.
pub fn parse_ipv4_strict(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        let v: u16 = p.parse().ok()?;
        out[i] = u8::try_from(v).ok()?;
    }
    Some(out)
}

pub fn fmt_ipv4(o: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn looks_dotted(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

fn resolve_to_ip(host: &str, label: &[PyChar], resolver: Resolver, log: &mut Vec<String>) -> Result<String, MapErr> {
    let stripped = py::strip_str(host);
    if looks_dotted(stripped) {
        return parse_ipv4_strict(stripped).map(fmt_ipv4).ok_or_else(|| {
            MapErr::Invalid(format!(
                "Invalid IPv4 address '{}' in {}",
                py::safe_str(stripped),
                py::safe(label)
            ))
        });
    }
    let answer = match resolver(stripped) {
        Ok(addrs) => addrs.into_iter().next(),
        Err(e) => {
            return Err(MapErr::Unresolved(format!(
                "Cannot resolve '{}' in {}: {}. Is the backend container running and on the same network?",
                py::safe_str(stripped),
                py::safe(label),
                py::safe_str(&e)
            )))
        }
    };
    // Re-parse the resolver's answer instead of trusting its formatting.
    let validated = answer
        .as_deref()
        .map(py::strip_str)
        .and_then(parse_ipv4_strict)
        .map(fmt_ipv4)
        .ok_or_else(|| {
            MapErr::Invalid(format!(
                "Resolver returned a non-IPv4 value {} for '{}' in {}; refusing to write it to the torrc",
                py::py_repr(answer.as_deref().unwrap_or("")),
                py::safe_str(stripped),
                py::safe(label)
            ))
        })?;
    log.push(format!("Resolved '{}' → {validated}", py::safe_str(stripped)));
    Ok(validated)
}

fn ends_with(s: &[PyChar], suffix: &str) -> bool {
    let suf = py::from_str(suffix);
    s.len() >= suf.len() && s[s.len() - suf.len()..] == suf[..]
}

/// str.replace(old, "") for every non-overlapping occurrence, left to right.
fn remove_all(s: &[PyChar], old: &str) -> PyStr {
    let o = py::from_str(old);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s.len() - i >= o.len() && s[i..i + o.len()] == o[..] {
            i += o.len();
        } else {
            out.push(s[i].clone());
            i += 1;
        }
    }
    out
}

fn lower_and_hyphenate(s: &[PyChar]) -> PyStr {
    let mut out = Vec::with_capacity(s.len());
    for c in s {
        match c {
            PyChar::C('_') => out.push(PyChar::C('-')),
            PyChar::C(ch) => out.extend(ch.to_lowercase().map(|l| if l == '_' { PyChar::C('-') } else { PyChar::C(l) })),
            PyChar::Surr(b) => out.push(PyChar::Surr(*b)),
        }
    }
    out
}

fn split_on(s: &[PyChar], sep: char) -> Vec<PyStr> {
    let mut out = vec![Vec::new()];
    for c in s {
        if *c == PyChar::C(sep) {
            out.push(Vec::new());
        } else {
            out.last_mut().map(|v| v.push(c.clone()));
        }
    }
    out
}

/// The environment the way CPython's os.environ presents it, sorted by key.
pub fn python_environ() -> Vec<(PyStr, PyStr)> {
    use std::os::unix::ffi::OsStrExt;
    let mut env: Vec<(PyStr, PyStr)> = std::env::vars_os()
        .map(|(k, v)| (py::decode(k.as_bytes()), py::decode(v.as_bytes())))
        .collect();
    env.sort_by(|a, b| a.0.iter().map(py::ord).cmp(b.0.iter().map(py::ord)));
    env
}

pub fn build(env: &[(PyStr, PyStr)], resolver: Resolver) -> Torrc {
    let mut out = Torrc::default();
    let sandbox = match env.iter().find(|(k, _)| *k == py::from_str("TOR_SANDBOX")) {
        Some((_, v)) if *v == py::from_str("0") => "0",
        _ => "1",
    };
    out.content = HEADER.replace("@SANDBOX@", sandbox);

    let mut found_any = false;
    let mut seen: Vec<(String, PyStr)> = Vec::new();
    for (env_var, service_hosts) in env {
        if !ends_with(env_var, SUFFIX) {
            continue;
        }
        let safe_env = py::safe(env_var);
        let safe_hosts = py::safe(service_hosts);
        let raw_name = lower_and_hyphenate(&remove_all(env_var, SUFFIX));

        let service_name = match validate_service_name(&raw_name) {
            Ok(n) => n,
            Err(e) => {
                out.log.push(format!("Skipping invalid service name from {safe_env}: {e}"));
                out.dropped.push(format!("{safe_env}: invalid service name: {e}"));
                continue;
            }
        };
        if let Some((_, first)) = seen.iter().find(|(n, _)| *n == service_name) {
            let first = py::safe(first);
            out.log.push(format!(
                "ERROR: {safe_env} maps to service '{service_name}', which is already defined by {first}; skipping it. \
                 Service names are lowercased and underscores become hyphens, so names that differ only in case or \
                 in _ vs - collide. Rename one."
            ));
            out.dropped.push(format!("{safe_env}: service name '{service_name}' collides with {first}"));
            continue;
        }
        seen.push((service_name.clone(), env_var.clone()));

        out.log.push(format!("Configuring hidden service: {service_name}"));
        out.log.push(format!("Service hosts: {safe_hosts}"));

        let hs_dir = format!("{KEYS_ROOT}/{service_name}");
        let mut block = format!("\n# ── Service: {service_name} ──\n");
        block += &format!("HiddenServiceDir     {hs_dir}\n");
        block += "HiddenServiceVersion 3\n";
        block += "HiddenServiceNumIntroductionPoints 6\n";
        block += "HiddenServiceMaxStreams 100\n";
        block += "HiddenServiceMaxStreamsCloseCircuit 1\n";
        block += "HiddenServicePoWDefensesEnabled 1\n";
        block += "HiddenServicePoWQueueRate  250\n";
        block += "HiddenServicePoWQueueBurst 2500\n";
        block += "HiddenServiceEnableIntroDoSDefense 1\n";
        block += "HiddenServiceEnableIntroDoSRatePerSec 25\n";
        block += "HiddenServiceEnableIntroDoSBurstPerSec 200\n";

        let mut port_lines: Vec<String> = Vec::new();
        for mapping in split_on(service_hosts, ',') {
            let stripped = py::strip(&mapping).to_vec();
            if !mapping.contains(&PyChar::C(':')) {
                if !stripped.is_empty() {
                    out.dropped.push(format!("{safe_env}: malformed mapping '{}'", py::safe(&stripped)));
                }
                continue;
            }
            let parts = split_on(&stripped, ':');
            let mut backend_name = String::new();
            let result: Result<(), MapErr> = (|| {
                match parts.len() {
                    3 => {
                        let hs_port = validate_port(&parts[0], &mapping).map_err(MapErr::Invalid)?;
                        let host = validate_hostname(&parts[1], &mapping).map_err(MapErr::Invalid)?;
                        backend_name.clone_from(&host);
                        let ip = resolve_to_ip(&host, &mapping, resolver, &mut out.log)?;
                        if backend_name != ip {
                            if let Some(slot) = out.resolved.iter_mut().find(|(n, _)| *n == backend_name) {
                                slot.1.clone_from(&ip);
                            } else {
                                out.resolved.push((backend_name.clone(), ip.clone()));
                            }
                        }
                        let target_port = validate_port(&parts[2], &mapping).map_err(MapErr::Invalid)?;
                        port_lines.push(format!("HiddenServicePort {hs_port} {ip}:{target_port}\n"));
                    }
                    2 => {
                        let hs_port = validate_port(&parts[0], &mapping).map_err(MapErr::Invalid)?;
                        let target_port = validate_port(&parts[1], &mapping).map_err(MapErr::Invalid)?;
                        port_lines.push(format!("HiddenServicePort {hs_port} 127.0.0.1:{target_port}\n"));
                    }
                    _ => {
                        out.log.push(format!("Skipping malformed mapping: '{}'", py::safe(&mapping)));
                        out.dropped.push(format!("{safe_env}: malformed mapping '{}'", py::safe(&stripped)));
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => {}
                Err(MapErr::Unresolved(e)) => {
                    out.log.push(format!("Skipping mapping '{}' for now: {e}", py::safe(&mapping)));
                    if !out.unresolved.contains(&backend_name) {
                        out.unresolved.push(backend_name.clone());
                    }
                    out.dropped.push(format!(
                        "{safe_env}: invalid mapping '{}': {e} It is added automatically once the name resolves.",
                        py::safe(&stripped)
                    ));
                }
                Err(MapErr::Invalid(e)) => {
                    out.log.push(format!("Skipping invalid mapping '{}': {e}", py::safe(&mapping)));
                    out.dropped.push(format!("{safe_env}: invalid mapping '{}': {e}", py::safe(&stripped)));
                }
            }
        }

        if port_lines.is_empty() {
            out.log.push(format!(
                "ERROR: service '{service_name}' has no valid port mappings (from {safe_env}='{safe_hosts}'); \
                 skipping it. Tor cannot start a hidden service with no ports, so emitting it would take down \
                 every other service too. Fix this mapping."
            ));
            out.dropped.push(format!("{safe_env}: no valid port mappings; service dropped"));
            continue;
        }
        out.content += &block;
        out.content += &port_lines.concat();
        out.hs_dirs.push(hs_dir);
        found_any = true;
    }
    if !found_any {
        out.log.push(
            "Warning: no *_TOR_SERVICE_HOSTS env vars found; Tor will start but no hidden services will be configured."
                .to_string(),
        );
    }
    out
}

/// socket.gethostbyname / gethostbyname_ex through libc getaddrinfo(AF_INET):
/// the addresses in resolver order, or `str(socket.gaierror)`.
pub fn libc_resolve(name: &str) -> Result<Vec<String>, String> {
    use std::ffi::{CStr, CString};
    let Ok(c) = CString::new(name) else {
        return Err("embedded null byte".to_string());
    };
    // SAFETY: zeroed addrinfo is a valid "no hints" value; we set family/socktype.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: valid C string, valid hints, out-pointer to a local.
    let rc = unsafe { libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        // SAFETY: gai_strerror returns a static NUL-terminated string.
        let msg = unsafe { CStr::from_ptr(libc::gai_strerror(rc)) }.to_string_lossy().into_owned();
        return Err(format!("[Errno {rc}] {msg}"));
    }
    let mut out = Vec::new();
    let mut p = res;
    while !p.is_null() {
        // SAFETY: p walks the list getaddrinfo returned; freed below.
        let ai = unsafe { &*p };
        if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
            // SAFETY: AF_INET entries carry a sockaddr_in.
            let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
            let o = u32::from_be(sin.sin_addr.s_addr).to_be_bytes();
            let s = fmt_ipv4(o);
            if !out.contains(&s) {
                out.push(s);
            }
        }
        p = ai.ai_next;
    }
    // SAFETY: res came from a successful getaddrinfo.
    unsafe { libc::freeaddrinfo(res) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(PyStr, PyStr)> {
        let mut v: Vec<(PyStr, PyStr)> = pairs.iter().map(|(k, v)| (py::from_str(k), py::from_str(v))).collect();
        v.sort_by(|a, b| a.0.iter().map(py::ord).cmp(b.0.iter().map(py::ord)));
        v
    }
    fn dns(name: &str) -> Result<Vec<String>, String> {
        match name {
            "web" => Ok(vec!["10.0.0.5".into()]),
            _ => Err("[Errno -2] Name does not resolve".into()),
        }
    }

    #[test]
    fn single_and_twopart() {
        let t = build(&env(&[("MYAPP_TOR_SERVICE_HOSTS", "80:10.0.0.2:8080,443:8443")]), &dns);
        assert!(t.content.contains("HiddenServicePort 80 10.0.0.2:8080\nHiddenServicePort 443 127.0.0.1:8443\n"));
        assert_eq!(t.hs_dirs, vec!["/var/lib/tor/hidden_service/myapp"]);
    }

    #[test]
    fn resolves_and_records() {
        let t = build(&env(&[("A_TOR_SERVICE_HOSTS", "80:web:80,81:gone:80")]), &dns);
        assert_eq!(t.resolved, vec![("web".to_string(), "10.0.0.5".to_string())]);
        assert_eq!(t.unresolved, vec!["gone".to_string()]);
        assert!(t.log.iter().any(|l| l == "Resolved 'web' → 10.0.0.5"));
    }

    #[test]
    fn rejects_bad_ipv4_and_injection() {
        let t = build(&env(&[("A_TOR_SERVICE_HOSTS", "80:010.0.0.1:80,80:1.2.3.4:80\nSocksPort 9050")]), &dns);
        assert!(!t.content.contains("SocksPort 9050"));
        assert!(t.hs_dirs.is_empty());
    }

    #[test]
    fn strict_ipv4() {
        assert_eq!(parse_ipv4_strict("127.0.0.1"), Some([127, 0, 0, 1]));
        assert!(parse_ipv4_strict("01.2.3.4").is_none());
        assert!(parse_ipv4_strict("256.1.1.1").is_none());
    }
}
